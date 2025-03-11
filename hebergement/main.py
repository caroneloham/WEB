import os
import threading
import socket
import shutil
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from werkzeug.utils import secure_filename

# Pour la génération de certificats
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ----------------- Configuration de base -----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SITE_PREFIX = "site_"
SITE_BASE_PORT = 8000    # Port de départ pour les sites (HTTP)
DASHBOARD_PORT = 5000    # Port du dashboard central

# Variables globales
sites_info = []        # Liste des sites, chaque entrée est un dict {name, port, url, https}
site_threads = {}      # Dictionnaire associant le nom du site à son thread
next_site_port = SITE_BASE_PORT  # Prochain port à attribuer

# Dictionnaire pour mémoriser le mode HTTPS pour chaque site (True/False)
site_https_flags = {}

# ----------------- Fonctions de génération de certificats pour chaque client -----------------
def generate_self_signed_cert_for_client(client_folder, common_name):
    """Génère un certificat auto-signé et une clé privée dans le dossier client."""
    cert_file = os.path.join(client_folder, "cert.pem")
    key_file = os.path.join(client_folder, "key.pem")
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrganization"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False,)
        .sign(key, hashes.SHA256())
    )
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[INFO] Certificat auto-signé généré pour {common_name} dans {client_folder}.")

def ensure_client_certificates(client_folder, common_name):
    """Vérifie que cert.pem et key.pem existent dans le dossier client ; sinon, les génère."""
    cert_file = os.path.join(client_folder, "cert.pem")
    key_file = os.path.join(client_folder, "key.pem")
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print(f"[INFO] Certificats introuvés pour {common_name} dans {client_folder}. Génération automatique...")
        generate_self_signed_cert_for_client(client_folder, common_name)

# ----------------- Récupération de l'IP de la machine -----------------
def get_machine_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # On se connecte à une adresse externe pour obtenir l'IP locale
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip

MACHINE_IP = get_machine_ip()

# ----------------- Fonctions de gestion des sites -----------------
def create_site_app(site_path):
    """
    Crée une instance Flask servant les fichiers du site situé dans site_path.
    """
    app = Flask(site_path)

    @app.route('/')
    def index():
        index_file = os.path.join(site_path, "index.html")
        if not os.path.exists(index_file):
            abort(404)
        return send_from_directory(site_path, "index.html")

    @app.route('/<path:filename>')
    def serve_file(filename):
        return send_from_directory(site_path, filename)

    return app

def run_site(site_name, port, use_https=False):
    """
    Lance l'application Flask pour le site donné sur le port spécifié.
    Si use_https est True, le serveur est lancé en HTTPS en utilisant les certificats du dossier client.
    """
    site_path = os.path.join(BASE_DIR, site_name)
    app = create_site_app(site_path)
    mode = "HTTPS" if use_https else "HTTP"
    print(f"[INFO] Lancement du site '{site_name}' sur le port {port} en {mode}...")
    try:
        if use_https:
            # Assure que le dossier du client possède ses certificats
            ensure_client_certificates(site_path, site_name)
            cert_file = os.path.join(site_path, "cert.pem")
            key_file = os.path.join(site_path, "key.pem")
            app.run(host='0.0.0.0', port=port, ssl_context=(cert_file, key_file),
                    debug=False, use_reloader=False)
        else:
            app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
    except Exception as e:
        print(f"[ERROR] Erreur sur le site {site_name} : {e}")

def start_site(site_name, port, use_https=False):
    """
    Démarre le serveur Flask pour le site donné dans un thread et enregistre ce thread.
    """
    t = threading.Thread(target=run_site, args=(site_name, port, use_https))
    t.daemon = True
    t.start()
    site_threads[site_name] = t

def create_new_client(client_name):
    """
    Crée un nouveau dossier de site avec un index.html basique, démarre son serveur et
    met à jour la liste globale et le flag HTTPS (initialement False).
    """
    global next_site_port, sites_info

    safe_name = secure_filename(client_name)
    if safe_name == "":
        raise ValueError("Nom invalide.")

    site_folder = SITE_PREFIX + safe_name
    site_path = os.path.join(BASE_DIR, site_folder)
    if os.path.exists(site_path):
        raise FileExistsError("Ce client existe déjà.")

    os.makedirs(site_path, exist_ok=True)
    # Optionnel : Vous pouvez créer ici d'autres fichiers spécifiques au client.
    index_path = os.path.join(site_path, "index.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(f"""<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8">
    <title>{client_name}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container mt-5">
      <div class="card shadow">
        <div class="card-header bg-primary text-white">
          Bienvenue chez {client_name}
        </div>
        <div class="card-body">
          <p class="card-text">Ceci est la page d'accueil de votre site.</p>
        </div>
      </div>
    </div>
  </body>
</html>
""")
    assigned_port = next_site_port
    next_site_port += 1

    # Par défaut, le HTTPS est désactivé pour le nouveau site
    site_https_flags[site_folder] = False
    start_site(site_folder, assigned_port, use_https=False)
    site_entry = {
        'name': site_folder,
        'port': assigned_port,
        'https': False,
        'url': f"http://{MACHINE_IP}:{assigned_port}/"
    }
    sites_info.append(site_entry)
    print(f"[INFO] Nouveau client '{site_folder}' créé sur le port {assigned_port} en HTTP.")
    return site_entry

def delete_site(site_name):
    """
    Supprime le dossier du site et retire ses références dans sites_info, site_threads et site_https_flags.
    """
    global sites_info, site_threads, site_https_flags
    site_path = os.path.join(BASE_DIR, site_name)
    if os.path.exists(site_path):
        try:
            shutil.rmtree(site_path)
            msg = f"Le site {site_name} a été supprimé."
            print(f"[INFO] {msg}")
        except Exception as e:
            msg = f"Erreur lors de la suppression du site {site_name} : {e}"
            print(f"[ERROR] {msg}")
            return msg
    else:
        msg = f"Le site {site_name} n'existe pas."
        print(f"[WARNING] {msg}")
        return msg

    sites_info = [s for s in sites_info if s['name'] != site_name]
    if site_name in site_threads:
        del site_threads[site_name]
    if site_name in site_https_flags:
        del site_https_flags[site_name]
    return f"Site {site_name} supprimé."

def init_existing_sites():
    """
    Parcourt BASE_DIR pour trouver tous les dossiers de sites existants,
    démarre leur serveur en respectant leur mode HTTPS et met à jour sites_info.
    """
    global next_site_port, sites_info
    for d in os.listdir(BASE_DIR):
        site_path = os.path.join(BASE_DIR, d)
        if os.path.isdir(site_path) and d.startswith(SITE_PREFIX):
            assigned_port = next_site_port
            next_site_port += 1
            use_https = site_https_flags.get(d, False)
            site_https_flags[d] = use_https
            url = f"https://{MACHINE_IP}:{assigned_port}/" if use_https else f"http://{MACHINE_IP}:{assigned_port}/"
            entry = {
                'name': d,
                'port': assigned_port,
                'https': use_https,
                'url': url
            }
            sites_info.append(entry)
            start_site(d, assigned_port, use_https=use_https)

# ----------------- Dashboard -----------------
def create_dashboard_app():
    """
    Crée l'application Flask du dashboard.
    Permet de créer, rafraîchir, supprimer des sites et de basculer entre HTTP et HTTPS.
    Pour éviter les conflits, lors du basculement, on change de port :
      - HTTP : port d'origine
      - HTTPS : port d'origine + 1000
    """
    app = Flask("dashboard", template_folder=os.path.join(BASE_DIR, "templates"))
    app.secret_key = "clé_très_secrète"  # Nécessaire pour flash()

    @app.route('/', methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            client_name = request.form.get("client_name", "").strip()
            if client_name == "":
                flash("Le nom du client est requis.", "danger")
            else:
                try:
                    create_new_client(client_name)
                    flash(f"Le client '{client_name}' a été créé.", "success")
                except Exception as e:
                    flash(str(e), "danger")
            return redirect(url_for("index"))
        return render_template('index.html', sites=sites_info, machine_ip=MACHINE_IP)

    @app.route('/refresh_all')
    def refresh_all():
        """
        Rafraîchit la liste des sites en rescanant BASE_DIR et redémarre chaque site
        en respectant son mode HTTPS.
        """
        global sites_info, site_threads, next_site_port
        sites_info.clear()
        next_site_port = SITE_BASE_PORT
        for d in os.listdir(BASE_DIR):
            site_path = os.path.join(BASE_DIR, d)
            if os.path.isdir(site_path) and d.startswith(SITE_PREFIX):
                assigned_port = next_site_port
                next_site_port += 1
                use_https = site_https_flags.get(d, False)
                url = f"https://{MACHINE_IP}:{assigned_port}/" if use_https else f"http://{MACHINE_IP}:{assigned_port}/"
                entry = {
                    'name': d,
                    'port': assigned_port,
                    'https': use_https,
                    'url': url
                }
                sites_info.append(entry)
                if d not in site_threads or not site_threads[d].is_alive():
                    start_site(d, assigned_port, use_https=use_https)
        flash("Rafraîchissement global effectué.", "info")
        return redirect(url_for("index"))

    @app.route('/refresh_site/<site_name>')
    def refresh_site(site_name):
        """
        Pour le site donné, redémarre son serveur en respectant son mode HTTPS.
        """
        for entry in sites_info:
            if entry['name'] == site_name:
                use_https = entry['https']
                start_site(site_name, entry['port'], use_https=use_https)
                flash(f"Le site {site_name} a été redémarré.", "success")
                break
        else:
            flash("Site inconnu.", "danger")
        return redirect(url_for("index"))

    @app.route('/delete_site/<site_name>')
    def delete_site_route(site_name):
        """
        Supprime le site et met à jour la liste.
        """
        msg = delete_site(site_name)
        flash(msg, "warning")
        return redirect(url_for("index"))

    @app.route('/toggle_https/<site_name>')
    def toggle_https(site_name):
        """
        Bascule le mode HTTPS pour le site donné.
        Pour éviter les conflits, on attribue un nouveau port lors de l'activation HTTPS (port d'origine + 1000)
        et on revient au port d'origine en désactivant HTTPS.
        """
        if site_name in site_https_flags:
            current_mode = site_https_flags[site_name]
            new_mode = not current_mode
            site_https_flags[site_name] = new_mode
            for entry in sites_info:
                if entry['name'] == site_name:
                    # Changement de port pour éviter conflit
                    if new_mode:
                        new_port = entry['port'] + 1000
                    else:
                        new_port = entry['port'] - 1000
                    entry['port'] = new_port
                    entry['https'] = new_mode
                    entry['url'] = f"https://{MACHINE_IP}:{new_port}/" if new_mode else f"http://{MACHINE_IP}:{new_port}/"
                    start_site(site_name, new_port, use_https=new_mode)
                    flash(f"Le site {site_name} est désormais en {'HTTPS' if new_mode else 'HTTP'} sur le port {new_port}.", "success")
                    break
        else:
            flash("Site inconnu.", "danger")
        return redirect(url_for("index"))

    return app

def run_dashboard(app, port):
    """
    Lance le dashboard sur le port spécifié.
    """
    print(f"[INFO] Lancement du dashboard sur le port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

# ----------------- Main -----------------
def main():
    init_existing_sites()
    dashboard_app = create_dashboard_app()
    dashboard_thread = threading.Thread(target=run_dashboard, args=(dashboard_app, DASHBOARD_PORT))
    dashboard_thread.daemon = True
    dashboard_thread.start()

    print("[INFO] Tous les sites et le dashboard ont été lancés.")
    print(f"Accès au dashboard : http://{MACHINE_IP}:{DASHBOARD_PORT}/")
    for site in sites_info:
        print(f" - {site['name']} : {site['url']}")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[INFO] Arrêt du programme.")

if __name__ == '__main__':
    main()

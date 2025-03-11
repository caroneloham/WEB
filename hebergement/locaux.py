import flask
@app.route('/toggle_https/<site_name>')
def toggle_https(site_name):
    """
    Bascule le mode HTTPS pour le site donné.
    Pour les tests, si l'on active HTTPS, on attribue un nouveau port (par exemple +1000).
    """
    if site_name in site_https_flags:
        # Inverse le valeur du flag HTTPS
        current_mode = site_https_flags[site_name]
        new_mode = not current_mode
        site_https_flags[site_name] = new_mode
        for entry in sites_info:
            if entry['name'] == site_name:
                # Si on passe en HTTPS, on attribue un nouveau port (par exemple, port + 1000)
                if new_mode:
                    new_port = entry['port'] + 1000
                else:
                    # Pour revenir en HTTP, on récupère le port d'origine (supposons qu'il soit enregistré dans entry)
                    # Ici, pour simplifier, on remet simplement le port d'origine en soustrayant 1000.
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

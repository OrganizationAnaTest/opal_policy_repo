package authz

default allow = false

import future.keywords.in

# Obtener el token OAuth de Entra ID
oauth_token() = token {
    client_id := getenv("CLIENT_ID")
    client_secret := getenv("CLIENT_SECRET")
    token_url := getenv("TOKEN_URL")

    response := http.send({
        "method": "POST",
        "url": token_url,
        "headers": { "Content-Type": "application/x-www-form-urlencoded" },
        "body": {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default"
        }
    })
    token := response.body.access_token
}

# Obtener grupos de un usuario en Entra ID
user_groups(user_email) = groups {
    token := oauth_token()

    response := http.send({
        "method": "GET",
        "url": sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf", [user_email]),
        "headers": {
            "Authorization": sprintf("Bearer %s", [token]),
            "Content-Type": "application/json"
        }
    })

    groups := [g.displayName | g := response.body.value]
}

# Verifica si el grupo del usuario tiene acceso al proceso
group_has_access_to_process(user_groups, process_id) {
    some group in user_groups
    group in data.process_group[process_id]
}

# Verifica si el proceso puede llamar a otro proceso (herencia de permisos)
process_inherits_access(requested_process_id, accessible_process_id) {
    some parent_process_id in data.process_relation[requested_process_id]
    accessible_process_id == parent_process_id
}

# Permitir si el email del usuario es manuel.cerezo@ejemplo.es
allow {
    input.user.email == "manuel.cerezo@ejemplo.es"
}

# Permiso basado en relación para tareas con `status=error`
#allow {
    #some process_id, task_id
    #input.user.email == user_email
    #user_groups(user_email)[group]
    
    #task_id in data.process_task[process_id]
    #data.tasks[task_id].status == "error"

    # El usuario debe tener acceso al proceso o a un proceso padre
    #group_has_access_to_process(user_groups(user_email), process_id) 
    #or process_inherits_access(process_id, accessible_process_id)
    
    # Validación de país
    #input.user.country == data.processes[process_id].country
#}


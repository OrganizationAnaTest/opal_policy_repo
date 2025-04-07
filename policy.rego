package authz

# Obtener el token OAuth de Entra ID
#oauth_token if {
#    response := http.send({
#        "method": "POST",
#        "url": "https://login.microsoftonline.com/TU_TENANT_ID/oauth2/v2.0/token",
#        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
#        "body": {
#            "grant_type": "client_credentials",
#            "client_id": "TU_CLIENT_ID",
#            "client_secret": "TU_CLIENT_SECRET",
#            "scope": "https://graph.microsoft.com/.default"
#       }
#    })
#    token := response.body.access_token
#}

# Obtener el token OAuth de Entra ID
oauth_token if {
    token := data.oauth.token # <-- accedes al token así
    trace(sprintf("Token de acceso: %s", [token]))  # Esto imprimirá el token para verificar que está siendo asignado correctamente
}

# Obtener grupos de un usuario de manera segura
user_groups[user_email] contains group if {
    # Obtener el email del input de manera controlada
    user_email := input.user.email
    response := http.send({
        "method": "GET",
        "url": sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf", [user_email]),
        "headers": {
            "Authorization": sprintf("Bearer %s", [oauth_token]),
            "Content-Type": "application/json"
        }
    })
    # Se asegura que la respuesta contenga datos seguros
    group := [g.displayName | g := response.body.value]
}

# Verifica si el grupo del usuario tiene acceso al proceso
group_has_access_to_process[process_id] contains true if {
    # Asegurar que el email del usuario proviene de input
    user_email := input.user.email
    group := user_groups[user_email]
    trace(sprintf("Grupo del usuario: %s", [group]))  # Asegúrate de que el grupo está correctamente asignado
    group in data.process_group[process_id]  # Verifica que el grupo esté listado para el proceso
}

# Verifica si el proceso puede llamar a otro proceso (herencia de permisos)
process_inherits_access[process_id] contains true if {
    some parent_process_id
    parent_process_id = data.process_relation[process_id][_]
    trace(sprintf("Proceso padre: %s", [parent_process_id]))  # Verifica que el proceso padre esté correctamente asignado
    parent_process_id in data.processes  # Asegúrate de que el proceso padre existe
}

# Permiso basado en relación para tareas con `status=error`
allow if {
    user_email := input.user.email
    trace(sprintf("Usuario: %s", [user_email]))

    process_id := input.process_id
    trace(sprintf("Proceso ID: %s", [process_id]))

    task_id := data.process_task[process_id]
    trace(sprintf("Tarea ID: %s", [task_id]))

    data.tasks[task_id].status == "error"
    trace("Tarea en estado 'error'")

    allow_process_access[process_id]
    trace(sprintf("Acceso al proceso %s permitido", [process_id]))

    input.user.country == data.processes[process_id].country {
    trace(sprintf("Validación de país: Usuario '%s' vs Proceso '%s'", [input.user.country, data.processes[process_id].country]))  # Imprime los valores para ver qué está pasando
    }
}

# Separamos las reglas para acceso por grupo o herencia
allow_process_access[process_id] contains true if {
    user_email := input.user.email
    trace(sprintf("Email del usuario: %s", [user_email]))  # Esto imprimirá el email del usuario
    user_email == "expected_email@domain.com"  # Puedes verificar si el email está correcto
    process_id := input.process_id
    trace(sprintf("ID del proceso: %s", [process_id]))  # Imprime el ID del proceso
    process_id == "expected_process_id"  # Puedes verificar si el proceso está bien definido
    group_has_access_to_process[process_id]
}

allow_process_access[process_id] contains true if {
    process_inherits_access[process_id]
}

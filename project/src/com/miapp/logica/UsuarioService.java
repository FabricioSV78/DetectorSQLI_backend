package com.miapp.logica;

public class UsuarioService {

    public String construirConsulta(String id) {
        // ❌ Este método debería validar la entrada antes de usarla
        return "SELECT * FROM usuarios WHERE id = " + id;
    }
}
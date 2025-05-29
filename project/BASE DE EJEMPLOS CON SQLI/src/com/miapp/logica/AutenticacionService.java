package com.miapp.logica;

import com.miapp.datos.UsuarioDAO;

public class AutenticacionService {

    private UsuarioDAO usuarioDAO = new UsuarioDAO();

    public boolean validarUsuario(String user, String pass) {
        // ❌ No valida los parámetros antes de pasarlos al DAO
        return usuarioDAO.login(user, pass);
    }
}
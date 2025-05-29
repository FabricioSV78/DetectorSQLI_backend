package com.miapp.presentacion;

import com.miapp.logica.AutenticacionService;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

public class LoginController {

    private AutenticacionService authService = new AutenticacionService();

    public void autenticar(HttpServletRequest request, Connection conn) {
        String username = request.getParameter("usuario");
        String password = request.getParameter("clave");

        // ❌ Acceso a DB directo en la capa presentación
        try {
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM usuarios WHERE usuario = '" + username + "' AND clave = '" + password + "'";
            stmt.executeQuery(query);
        } catch (Exception e) {
            e.printStackTrace();
        }

        authService.validarUsuario(username, password); // ❌ Se pasa entrada sin validar
    }
}
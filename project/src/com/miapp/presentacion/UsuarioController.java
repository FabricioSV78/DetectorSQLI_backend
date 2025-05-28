package com.miapp.presentacion;

import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UsuarioController {

    public void procesar(HttpServletRequest request, Connection conn) {
        String id = request.getParameter("id"); // entrada de usuario

        try {
            Statement stmt = conn.createStatement(); // ❌ Mala práctica fuera de DAO
            String sql = "SELECT * FROM usuarios WHERE id = " + id; // ❌ concatenación
            stmt.executeQuery(sql);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
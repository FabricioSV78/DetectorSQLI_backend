package com.miapp.datos;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UsuarioDAO {

    public ResultSet buscarPorId(Connection conn, String id) throws Exception {
        // ✅ Forma segura (sin vulnerabilidad):
        String query = "SELECT * FROM usuarios WHERE id = ?";
        PreparedStatement ps = conn.prepareStatement(query);
        ps.setString(1, id);
        return ps.executeQuery();
    }

    public void ejemploInseguro(Connection conn, String id) throws Exception {
        // ❌ Mala práctica incluso en la capa DAO:
        String query = "SELECT * FROM usuarios WHERE id = " + id;
        conn.createStatement().executeQuery(query);
    }
}
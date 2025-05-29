package com.miapp.datos;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class UsuarioDAO {

    public boolean login(String user, String pass) {
        try {
            // ❌ SQLi por concatenación en DAO
            String query = "SELECT * FROM usuarios WHERE usuario = '" + user + "' AND clave = '" + pass + "'";
            Statement stmt = ConexionBD.getConnection().createStatement();
            ResultSet rs = stmt.executeQuery(query);
            return rs.next();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean loginSeguro(String user, String pass) {
        try {
            // ✅ Forma segura usando PreparedStatement
            String query = "SELECT * FROM usuarios WHERE usuario = ? AND clave = ?";
            PreparedStatement ps = ConexionBD.getConnection().prepareStatement(query);
            ps.setString(1, user);
            ps.setString(2, pass);
            ResultSet rs = ps.executeQuery();
            return rs.next();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
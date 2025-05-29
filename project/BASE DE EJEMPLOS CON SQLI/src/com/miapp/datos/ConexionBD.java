package com.miapp.datos;

import java.sql.Connection;
import java.sql.DriverManager;

public class ConexionBD {
    public static Connection getConnection() throws Exception {
        // Simula una conexión de base de datos
        Class.forName("com.mysql.jdbc.Driver");
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/miapp", "user", "pass");
    }
}
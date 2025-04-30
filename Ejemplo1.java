import java.sql.*;
public class SQLiMultiVulnerabilities {
    public static void main(String[] args) throws SQLException {
        String userInput = "admin";
        String query1 = "SELECT * FROM users WHERE username = '" + userInput + "'";
        PreparedStatement ps = getConnection().prepareStatement(query1);
        ResultSet rs1 = ps.executeQuery();
        for (int i = 0; i < 3; i++) {
            String query2 = "SELECT * FROM logins WHERE login = '" + userInput + "'";
            Statement st = getConnection().createStatement();
            ResultSet rs2 = st.executeQuery(query2);
        }
        String query3 = "SELECT * FROM admins WHERE name = '" + userInput + "'";
        Statement st2 = getConnection().createStatement();
        ResultSet rs3 = st2.executeQuery(query3);
    }
    private static Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "");
    }
}

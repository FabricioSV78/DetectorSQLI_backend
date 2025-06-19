
import os
import tempfile
from detector import SQLiDetector, analizar_proyecto
from antlr4 import *
from JavaLexer import JavaLexer
from JavaParser import JavaParser
from antlr4.CommonTokenStream import CommonTokenStream
from antlr4.FileStream import FileStream

def analizar_codigo_java(codigo_str):
    # Crear archivo temporal
    with tempfile.NamedTemporaryFile(delete=False, suffix=".java", mode='w', encoding='utf-8') as tmp:
        tmp.write(codigo_str)
        tmp_path = tmp.name

    input_stream = FileStream(tmp_path, encoding='utf-8')
    lexer = JavaLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = JavaParser(stream)
    tree = parser.compilationUnit()

    detector = SQLiDetector(tmp_path)
    walker = ParseTreeWalker()
    walker.walk(detector, tree)

    os.remove(tmp_path)
    return detector.alertas_por_linea

def test_violacion_arquitectura():
    codigo = '''
        package presentacion;
        import java.sql.Connection;
        import java.sql.Statement;

        public class LoginController {
            private Connection conn;

            public void login(String usuario) {
                try {
                    Statement stmt = conn.createStatement();
                    String sql = "SELECT * FROM usuarios WHERE nombre='" + usuario + "'";
                    stmt.execute(sql);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    '''
    alertas = analizar_codigo_java(codigo)
    print(alertas)
    tipos = [a["tipo"] for lista in alertas.values() for a in lista]
    assert "Violación de arquitectura" in tipos
    assert "SQLi por uso de parámetro no validado" in tipos  # opcionalmente


def test_inyeccion_sql_por_concatenacion():
    codigo = '''
        package datos;
        import java.sql.Statement;

        public class UsuarioDAO {
            public void buscar(String id) {
                Statement stmt = conn.createStatement();
                stmt.execute("SELECT * FROM usuarios WHERE id=" + id);
            }
        }
    '''
    alertas = analizar_codigo_java(codigo)
    print(alertas)
    tipos = [a["tipo"] for lista in alertas.values() for a in lista]
    assert "SQLi por concatenación" in tipos




def test_prepared_statement_seguro():
    codigo = '''
        package datos;

        import java.sql.*;

        public class ReservaDAO {
            public void insertar(String usuario, int libroId) throws SQLException {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
                String sql = "INSERT INTO reservas (usuario, libro_id) VALUES (?, ?)";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, usuario);
                ps.setInt(2, libroId);
                ps.executeUpdate();
            }
        }
    '''
    alertas = analizar_codigo_java(codigo)
    print(alertas)
    tipos = [a["tipo"] for lista in alertas.values() for a in lista]
    assert "SQLi por uso de parámetro no validado" not in tipos
    


def test_codigo_sin_sql():
    codigo = '''
        public class Utilidad {
            public void imprimir(String mensaje) {
                System.out.println(mensaje);
            }
        }
    '''
    alertas = analizar_codigo_java(codigo)
    assert not alertas


def test_analizar_proyecto_basico(tmp_path):
    proyecto_dir = tmp_path / "test_project"
    proyecto_dir.mkdir()

    archivo = proyecto_dir / "TestDAO.java"
    archivo.write_text("""
        package datos;
        public class TestDAO {
            public void buscar(String input) {
                String sql = "SELECT * FROM tabla WHERE valor=" + input;
            }
        }
    """, encoding='utf-8')

    resultados, stats, grafo = analizar_proyecto(str(proyecto_dir))

    assert stats["archivos analizados"] == 1
    assert stats["lineas afectadas"] >= 1
    assert grafo.number_of_nodes() > 0

    tipos = [detalle.split(":")[0].replace("[CRÍTICO] ", "") 
             for a in resultados 
             for detalle in a["detalles"]]

    assert "SQLi por uso de parámetro no validado" in tipos
    assert any("valor=" in a["codigo"] for a in resultados)



import java.sql.Connection;
import java.sql.Statement;

public class ExcludedSinkExample {
    public void findAccountsByIdOk() throws SQLException {
        String id = "const";
        String sql = String.format("SELECT * FROM accounts WHERE id = '%s'", id);
        Connection c = db.getConnection();
        // ok:formatted-sql-string
        ResultSet rs = c.createStatement().execute(sql);
    }
}

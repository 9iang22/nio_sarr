@RestController
@EnableAutoConfiguration
public class TestController {
    @RequestMapping(value = "/testok4", method = RequestMethod.POST, produces = "plain/text")
    ResultSet ok4(@RequestBody Boolean name) {
        String sql = "SELECT * FROM table WHERE name = ";
        // ok: tainted-sql-string
        sql += name + ";";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:8080", "guest", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.execute(sql);
        return rs;
    }
}
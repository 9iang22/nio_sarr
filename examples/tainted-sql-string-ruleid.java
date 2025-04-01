class Foo {
  List<Bar> bars;

  public List<Bar> getBars(String name) {
    return bars;
  }
}

class Test {
  @RequestMapping(value = "/testok6", method = RequestMethod.POST, produces = "plain/text")
  public ResultSet ok7(@RequestBody String name, Foo foo) {
        var v = foo.getBars(name).get(0).getX();
        String sql = "SELECT * FROM table WHERE name = ";
        // ok in pro engine
        // ruleid: tainted-sql-string
        sql += v + ";";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:8080", "guest", "password");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.execute(sql);
        return rs;
  }
}

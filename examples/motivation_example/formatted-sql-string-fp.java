public class SQLExample3 {

    public List<AccountDTO> findAccountsById(String id, CriteriaBuilder cb) {
        String jql = String.format("from Account where id = '%s'", id);
        String jql_ = StringEscapeUtils.escapeSql(jql)
        EntityManager em = emfactory.createEntityManager();
        // ruleid: formatted-sql-string
        TypedQuery<Account> q = em.createQuery(jql_, Account.class);
        return q.getResultList()
        .stream()
        .map(this::toAccountDTO)
        .collect(Collectors.toList());
    }
}

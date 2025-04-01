package sql.injection;

import com.biz.org.AccountDTO;
import com.biz.org.DB;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.persistence.Query;
import javax.persistence.criteria.CriteriaBuilder;

public class FalsePositiveCase {
    public List<Student> addWhere(String name, CriteriaQuery Query)
    {
        EntityManager em = emfactory.createEntityManager();
    	CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		// ok: formatted-sql-string
        List<Student> students = em.createQuery(Query.where(criteriaBuilder.equal(studentRoot.get("name"), name ))).getResultList();
        return students;
    }
}

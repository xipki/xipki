// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.sql.*;
import java.time.Instant;
import java.util.*;
import javax.sql.DataSource;

/**
 * Parameterized JDBC operations; connections join the current local transaction.
 *
 * @author palos
 */
public final class Jdbc {
  @FunctionalInterface
  public interface RowMapper<T> {
    T mapRow(ResultSet result, int row) throws SQLException;
  }

  @FunctionalInterface
  public interface ConnectionWork<T> {
    T run(Connection connection) throws SQLException;
  }

  static final class Transaction {
    final Connection connection;
    boolean rollbackOnly;

    Transaction(Connection connection) {
      this.connection = connection;
    }
  }

  final ThreadLocal<Transaction> current = new ThreadLocal<>();
  private final DataSource source;

  public Jdbc(DataSource source) {
    this.source = Objects.requireNonNull(source);
  }

  public DataSource getDataSource() {
    return source;
  }

  public <T> T connection(ConnectionWork<T> work) {
    Transaction tx = current.get();
    if (tx != null) {
      try {
        return work.run(tx.connection);
      } catch (SQLException ex) {
        tx.rollbackOnly = true;
        throw failure(ex);
      }
    }
    try (Connection connection = source.getConnection()) {
      return work.run(connection);
    } catch (SQLException ex) {
      throw failure(ex);
    }
  }

  public int update(String sql, Object... args) {
    return connection(
        c -> {
          try (PreparedStatement statement = prepare(c, sql, args)) {
            return statement.executeUpdate();
          }
        });
  }

  /** Inserts a row only when its key is absent, using each supported database's native syntax. */
  public int insertIfAbsent(String insertSql, Object... args) {
    return connection(
        c -> {
          boolean postgres =
              c.getMetaData()
                  .getDatabaseProductName()
                  .toLowerCase(Locale.ROOT)
                  .contains("postgresql");
          String sql =
              postgres
                  ? insertSql + " ON CONFLICT DO NOTHING"
                  : insertSql.replaceFirst("(?i)^INSERT\\s+INTO", "INSERT IGNORE INTO");
          try (PreparedStatement statement = prepare(c, sql, args)) {
            return statement.executeUpdate();
          }
        });
  }

  public long insert(String sql, Object... args) {
    return connection(
        c -> {
          try (PreparedStatement statement =
              c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            bind(statement, args);
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
              if (!keys.next()) {
                throw new SQLException("No generated key");
              }
              return keys.getLong(1);
            }
          }
        });
  }

  public void execute(String sql) {
    connection(
        c -> {
          try (Statement statement = c.createStatement()) {
            statement.setQueryTimeout(5);
            statement.execute(sql);
            return null;
          }
        });
  }

  public <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {
    return connection(
        c -> {
          try (PreparedStatement statement = prepare(c, sql, args);
              ResultSet rows = statement.executeQuery()) {
            List<T> result = new ArrayList<>();
            int index = 0;
            while (rows.next()) {
              result.add(mapper.mapRow(rows, index++));
            }
            return result;
          }
        });
  }

  public <T> T queryForObject(String sql, Class<T> type, Object... args) {
    List<T> values = queryForList(sql, type, args);
    if (values.size() != 1) {
      throw new DataAccessException("Expected a single database row", null);
    }
    return values.get(0);
  }

  public <T> List<T> queryForList(String sql, Class<T> type, Object... args) {
    return query(sql, (result, row) -> scalar(result.getObject(1), type), args);
  }

  public List<Map<String, Object>> queryForList(String sql, Object... args) {
    return query(
        sql,
        (result, row) -> {
          Map<String, Object> values = new LinkedHashMap<>();
          ResultSetMetaData metadata = result.getMetaData();
          for (int i = 1; i <= metadata.getColumnCount(); i++) {
            values.put(metadata.getColumnLabel(i), result.getObject(i));
          }
          return values;
        },
        args);
  }

  private static PreparedStatement prepare(Connection connection, String sql, Object[] args)
      throws SQLException {
    PreparedStatement statement = connection.prepareStatement(sql);
    try {
      bind(statement, args);
      return statement;
    } catch (SQLException | RuntimeException ex) {
      statement.close();
      throw ex;
    }
  }

  private static void bind(PreparedStatement statement, Object[] args) throws SQLException {
    statement.setQueryTimeout(5);
    for (int i = 0; i < args.length; i++) {
      Object value = args[i];
      if (value instanceof Instant instant) {
        value = Timestamp.from(instant);
      }
      statement.setObject(i + 1, value);
    }
  }

  private static <T> T scalar(Object value, Class<T> type) {
    if (value == null) {
      return null;
    }
    if (type.isInstance(value)) {
      return type.cast(value);
    }
    Object converted;
    if (type == String.class) {
      converted = value.toString();
    } else if (value instanceof Number number && type == Long.class) {
      converted = number.longValue();
    } else if (value instanceof Number number && type == Integer.class) {
      converted = Math.toIntExact(number.longValue());
    } else if (value instanceof Boolean bool && type == Integer.class) {
      converted = bool ? 1 : 0;
    } else if (value instanceof Number number && type == Boolean.class) {
      converted = number.longValue() != 0;
    } else {
      throw new DataAccessException("Unsupported database scalar type", null);
    }
    return type.cast(converted);
  }

  static DataAccessException failure(SQLException ex) {
    return ex.getErrorCode() == 1062 || "23505".equals(ex.getSQLState())
        ? new DuplicateKeyException(ex)
        : new DataAccessException("Database operation failed", ex);
  }

  public static class DataAccessException extends RuntimeException {
    public DataAccessException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static final class DuplicateKeyException extends DataAccessException {
    public DuplicateKeyException(SQLException cause) {
      super("Duplicate database key", cause);
    }
  }
}

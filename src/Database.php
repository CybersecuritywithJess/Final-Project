<?php

/**
 * Thin PDO wrapper. Every query in this project goes through here, and every
 * one of them is a prepared statement — that is the project's answer to SQL
 * injection, and there is no string-concatenated SQL anywhere in the codebase.
 */
class Database
{
    private static ?PDO $pdo = null;

    public static function connect(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        $config = require __DIR__ . '/../config/config.php';
        $db = $config['db'];

        $dsn = "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}";

        try {
            self::$pdo = new PDO($dsn, $db['user'], $db['pass'], [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'Cannot connect to the database. Is MySQL running in XAMPP?',
                'detail' => $e->getMessage(),
            ]);
            exit;
        }

        return self::$pdo;
    }

    /** Run a query and return every row. */
    public static function all(string $sql, array $params = []): array
    {
        $stmt = self::connect()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /** Run a query and return the first row, or null. */
    public static function one(string $sql, array $params = []): ?array
    {
        $stmt = self::connect()->prepare($sql);
        $stmt->execute($params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Run a query and return a single scalar value from the first row. */
    public static function value(string $sql, array $params = [])
    {
        $row = self::one($sql, $params);
        return $row === null ? null : reset($row);
    }

    /** Execute a write. Returns the number of affected rows. */
    public static function run(string $sql, array $params = []): int
    {
        $stmt = self::connect()->prepare($sql);
        $stmt->execute($params);
        return $stmt->rowCount();
    }

    /** Execute an INSERT and return the new row's id. */
    public static function insert(string $sql, array $params = []): int
    {
        $pdo = self::connect();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return (int) $pdo->lastInsertId();
    }

    public static function begin(): void
    {
        self::connect()->beginTransaction();
    }

    public static function commit(): void
    {
        self::connect()->commit();
    }

    public static function rollback(): void
    {
        if (self::connect()->inTransaction()) {
            self::connect()->rollBack();
        }
    }
}

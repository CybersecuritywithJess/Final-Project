<?php

/** JSON responses and request-body parsing for the API endpoints. */
class Response
{
    public static function json(array $data, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function error(string $message, int $status = 400, array $extra = []): never
    {
        self::json(array_merge(['error' => $message], $extra), $status);
    }

    /** Decode the JSON request body into an array. */
    public static function body(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === '' || $raw === false) {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    /** Send a CSV file as a download. */
    public static function csv(array $rows, array $columns, string $filename): never
    {
        header('Content-Type: text/csv; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"$filename\"");

        $out = fopen('php://output', 'w');
        fputcsv($out, $columns);
        foreach ($rows as $row) {
            fputcsv($out, array_map(fn($c) => $row[$c] ?? '', $columns));
        }
        fclose($out);
        exit;
    }
}

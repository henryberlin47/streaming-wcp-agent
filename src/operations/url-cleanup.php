<?php
/**
 * Serialization-safe, DB-level URL rewrite.
 * Port of the cleanup-urls-site.sh embedded engine (no WordPress bootstrap).
 *
 * Everything arrives through the environment, never argv, so the DB
 * password never appears in the process list.
 */
declare(strict_types=1);

const BATCH       = 500;
const SKIPPED_CAP = 10;

final class UnsupportedShape extends RuntimeException {}

function env_req(string $k): string {
    $v = getenv($k);
    if ($v === false || $v === '') { fwrite(STDERR, "missing env {$k}\n"); exit(2); }
    return $v;
}

$mode   = env_req('UC_MODE');            // audit | replace | home
$host   = env_req('UC_DB_HOST');
$port   = (int) (getenv('UC_DB_PORT') ?: '3306');
$dbname = env_req('UC_DB_NAME');
$dbuser = env_req('UC_DB_USER');
$dbpass = (string) (getenv('UC_DB_PASSWORD') ?: '');
$prefix = (string) (getenv('UC_DB_PREFIX') ?: 'wp_');

$opts = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false];
if (filter_var((string) (getenv('UC_DB_SSL') ?: ''), FILTER_VALIDATE_BOOLEAN)) {
    $opts[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
}
try {
    $pdo = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $dbname),
                   $dbuser, $dbpass, $opts);
} catch (PDOException $e) {
    // The message names the user and whether a password was sent — never the password.
    fwrite(STDERR, 'DB connection failed: ' . $e->getMessage() . "\n");
    exit(3);
}

if ($mode === 'home') {
    $st = $pdo->prepare("SELECT option_value FROM `{$prefix}options` WHERE option_name = 'home' LIMIT 1");
    $st->execute();
    echo (string) ($st->fetchColumn() ?: '(unknown)'), "\n";
    exit(0);
}

$old = env_req('UC_OLD_URL');
$new = env_req('UC_NEW_URL');
if ($old === $new) { fwrite(STDERR, "old and new URL are identical\n"); exit(2); }

// MariaDB names it max_statement_time (seconds); MySQL max_execution_time (ms).
try { $pdo->exec('SET SESSION max_statement_time = 60'); }
catch (Throwable $e) { try { $pdo->exec('SET SESSION max_execution_time = 60000'); } catch (Throwable $e2) {} }

/**
 * A = plain text, never serialized -> one UPDATE ... REPLACE() per column.
 * B = may hold serialized values   -> keyset paginate + serialize-safe rewrite.
 * `wp_users` is absent on purpose: never rewrite password hashes or emails.
 * `guid` and `post_name` are absent: rewriting them breaks feeds and permalinks.
 */
$MAP = [
    'posts'         => ['pk' => 'ID',               's' => 'A', 'cols' => ['post_content', 'post_excerpt', 'post_title', 'post_content_filtered']],
    'comments'      => ['pk' => 'comment_ID',       's' => 'A', 'cols' => ['comment_content', 'comment_author_url']],
    'terms'         => ['pk' => 'term_id',          's' => 'A', 'cols' => ['name']],
    'term_taxonomy' => ['pk' => 'term_taxonomy_id', 's' => 'A', 'cols' => ['description']],
    'postmeta'      => ['pk' => 'meta_id',          's' => 'B', 'cols' => ['meta_value']],
    'options'       => ['pk' => 'option_id',        's' => 'B', 'cols' => ['option_value']],
    'termmeta'      => ['pk' => 'meta_id',          's' => 'B', 'cols' => ['meta_value']],
    'commentmeta'   => ['pk' => 'meta_id',          's' => 'B', 'cols' => ['meta_value']],
    'usermeta'      => ['pk' => 'umeta_id',         's' => 'B', 'cols' => ['meta_value']],
];

$only = trim((string) (getenv('UC_TABLES') ?: ''));
if ($only !== '') {
    $keep = preg_split('/\s+/', $only);
    $MAP  = array_intersect_key($MAP, array_flip($keep));
    if (!$MAP) { fwrite(STDERR, "UC_TABLES matched no known tables\n"); exit(2); }
}

function like_escape(string $s): string { return addcslashes($s, '\\%_'); }

function tree_has_object($n): bool {
    if (is_object($n)) return true;
    if (is_array($n)) { foreach ($n as $v) { if (tree_has_object($v)) return true; } }
    return false;
}

function walk_replace($n, string $old, string $new) {
    if (is_string($n)) return str_replace($old, $new, $n);
    if (is_array($n)) {
        $out = [];
        foreach ($n as $k => $v) {
            $nk = is_string($k) ? str_replace($old, $new, $k) : $k;
            $out[$nk] = walk_replace($v, $old, $new);
        }
        return $out;
    }
    return $n;
}

/** @return array{0:string,1:bool}|null  [newValue, wasSerialized] or null when unchanged */
function safe_replace(string $in, string $old, string $new): ?array {
    if ($in === '' || strpos($in, $old) === false) return null;

    if (preg_match('/^[abdiosCNOR][:;]/', $in)) {
        // Objects, classes and back-references cannot be round-tripped safely.
        if (preg_match('/^[OCR]:/', $in)) throw new UnsupportedShape(substr($in, 0, 2));

        $tree = @unserialize($in, ['allowed_classes' => false]);
        if ($tree !== false || $in === 'b:0;') {
            // allowed_classes=false turns nested objects into incomplete classes.
            if (tree_has_object($tree)) throw new UnsupportedShape('nested-object');
            $rebuilt = serialize(walk_replace($tree, $old, $new));
            if ($rebuilt === $in) return null;
            if (@unserialize($rebuilt, ['allowed_classes' => false]) === false && $rebuilt !== 'b:0;') {
                throw new UnsupportedShape('reserialize-failed');
            }
            return [$rebuilt, true];
        }
        // Looked serialized but wasn't — fall through to a plain replace.
    }

    $out = str_replace($old, $new, $in);
    return $out === $in ? null : [$out, false];
}

$needle = '%' . like_escape($old) . '%';
$T = ['matched' => 0, 'updated' => 0, 'serialized' => 0, 'skipped' => 0];

foreach ($MAP as $short => $spec) {
    $table = $prefix . $short;
    foreach ($spec['cols'] as $col) {
        $st = $pdo->prepare("SELECT COUNT(*) FROM `{$table}` WHERE `{$col}` LIKE ?");
        $st->execute([$needle]);
        $matched = (int) $st->fetchColumn();
        $T['matched'] += $matched;

        if ($mode === 'audit' || $matched === 0) {
            if ($matched > 0) printf("  %-38s matched=%d\n", "{$table}.{$col}", $matched);
            continue;
        }

        $updated = 0; $serialized = 0; $skipped = 0; $skippedIds = [];

        if ($spec['s'] === 'A') {
            $up = $pdo->prepare("UPDATE `{$table}` SET `{$col}` = REPLACE(`{$col}`, ?, ?) WHERE `{$col}` LIKE ?");
            $up->execute([$old, $new, $needle]);
            $updated = $up->rowCount();
        } else {
            $pk = $spec['pk'];
            $sel = $pdo->prepare(
                "SELECT `{$pk}` AS pk, `{$col}` AS col FROM `{$table}`
                  WHERE `{$pk}` > ? AND `{$col}` LIKE ?
                  ORDER BY `{$pk}` ASC LIMIT " . BATCH
            );
            $lastId = 0;
            while (true) {
                $sel->execute([$lastId, $needle]);
                $rows = $sel->fetchAll(PDO::FETCH_ASSOC);
                if (!$rows) break;

                $updates = [];
                foreach ($rows as $row) {
                    $lastId = (int) $row['pk'];
                    try {
                        $res = safe_replace((string) $row['col'], $old, $new);
                        if ($res !== null) {
                            $updates[] = [$lastId, $res[0]];
                            if ($res[1]) $serialized++;
                        }
                    } catch (UnsupportedShape $e) {
                        $skipped++;
                        if (count($skippedIds) < SKIPPED_CAP) $skippedIds[] = $lastId;
                    }
                }

                if ($updates) {
                    $cases = str_repeat(' WHEN ? THEN ?', count($updates));
                    $in    = implode(',', array_fill(0, count($updates), '?'));
                    $args  = [];
                    foreach ($updates as $u) { $args[] = $u[0]; $args[] = $u[1]; }
                    foreach ($updates as $u) { $args[] = $u[0]; }
                    $pdo->prepare("UPDATE `{$table}` SET `{$col}` = CASE `{$pk}`{$cases} END WHERE `{$pk}` IN ({$in})")
                        ->execute($args);
                    $updated += count($updates);
                }
            }
        }

        $T['updated'] += $updated; $T['serialized'] += $serialized; $T['skipped'] += $skipped;
        $extra = $serialized ? sprintf(' serialized=%d', $serialized) : '';
        if ($skipped) $extra .= sprintf(' skipped=%d (ids: %s)', $skipped, implode(',', $skippedIds));
        printf("  %-38s matched=%-6d updated=%-6d%s\n", "{$table}.{$col}", $matched, $updated, $extra);
    }
}

printf("SUMMARY matched=%d updated=%d serialized=%d skipped=%d\n",
    $T['matched'], $T['updated'], $T['serialized'], $T['skipped']);

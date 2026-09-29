<?php
// Run by the agent through `wp eval-file scripts/wp-set-password.php <user-id>`.
// The new password arrives on STDIN — never in argv, where `ps` could see it —
// and every existing session of that user is ended.
$id = isset($args[0]) ? (int) $args[0] : 0;
$pw = trim((string) fgets(STDIN));
if ($id < 1 || !get_userdata($id)) { fwrite(STDERR, "no such user id\n"); exit(2); }
if (strlen($pw) < 16) { fwrite(STDERR, "refusing a password shorter than 16 characters\n"); exit(3); }
wp_set_password($pw, $id);
WP_Session_Tokens::get_instance($id)->destroy_all();
echo "ok";

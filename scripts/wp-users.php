<?php
// Run by the agent:  wp eval-file scripts/wp-users.php <action>   (input: JSON on STDIN)
//
// Every WordPress-user action in ONE process, so each is atomic and the guards
// (never remove the last administrator, never orphan content) sit next to the
// change they protect. Passwords arrive on STDIN — never in argv, where `ps`
// could see them. The answer is one line, "WCP_JSON:{…}", so PHP notices in
// front of it do no harm.
//
// "Deactivate" is not a WordPress concept. Here it means: remember the roles in
// user meta, remove them all, scramble the password and end every session. The
// account keeps its content and can be activated again (roles restored, new
// password). A deactivated user who resets their password by e-mail still has
// no role, so they can reach nothing but their own profile.

$action = isset($args[0]) ? (string) $args[0] : '';
$in = json_decode((string) stream_get_contents(STDIN), true);
if (!is_array($in)) { $in = array(); }
define('WCP_PREV_ROLES', '_wcp_prev_roles');

function wcp_out($data) { echo "WCP_JSON:" . wp_json_encode($data) . "\n"; exit(0); }
function wcp_fail($msg) { echo "WCP_JSON:" . wp_json_encode(array('error' => $msg)) . "\n"; exit(1); }

function wcp_row($u) {
    $prev = get_user_meta($u->ID, WCP_PREV_ROLES, true);
    return array(
        'id' => (int) $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'name' => $u->display_name,
        'roles' => array_values($u->roles), 'registered' => $u->user_registered,
        'deactivated' => is_string($prev) && $prev !== '',
    );
}
function wcp_user($in) {
    $u = get_userdata(isset($in['id']) ? (int) $in['id'] : 0);
    if (!$u) { wcp_fail('no such user'); }
    return $u;
}
function wcp_password($in) {
    $p = isset($in['password']) ? (string) $in['password'] : '';
    if (strlen($p) < 16) { wcp_fail('refusing a password shorter than 16 characters'); }
    return $p;
}
function wcp_role($in) {
    $r = isset($in['role']) ? (string) $in['role'] : '';
    if (!wp_roles()->is_role($r)) { wcp_fail('unknown role: ' . $r); }
    return $r;
}
// true when removing $u's administrator role would leave the site with no administrator
function wcp_last_admin($u) {
    if (!in_array('administrator', (array) $u->roles, true)) { return false; }
    return count(get_users(array('role' => 'administrator', 'fields' => 'ID'))) <= 1;
}
function wcp_end_sessions($id) { WP_Session_Tokens::get_instance($id)->destroy_all(); }

switch ($action) {
    case 'list':
        $roles = array();
        foreach (wp_roles()->roles as $key => $def) { $roles[] = array('role' => $key, 'name' => translate_user_role($def['name'])); }
        wcp_out(array('users' => array_map('wcp_row', get_users(array('orderby' => 'ID', 'number' => 500))), 'roles' => $roles));

    case 'create':
        $login = isset($in['login']) ? sanitize_user((string) $in['login'], true) : '';
        $email = isset($in['email']) ? sanitize_email((string) $in['email']) : '';
        if ($login === '' || !validate_username($login)) { wcp_fail('invalid user login'); }
        if (username_exists($login)) { wcp_fail('a user with that login already exists'); }
        if (!is_email($email)) { wcp_fail('invalid e-mail address'); }
        if (email_exists($email)) { wcp_fail('a user with that e-mail already exists'); }
        $id = wp_insert_user(array('user_login' => $login, 'user_email' => $email, 'user_pass' => wcp_password($in), 'role' => wcp_role($in)));
        if (is_wp_error($id)) { wcp_fail($id->get_error_message()); }
        wcp_out(array('user' => wcp_row(get_userdata($id))));

    case 'reset':
        $u = wcp_user($in);
        if (get_user_meta($u->ID, WCP_PREV_ROLES, true)) { wcp_fail('this user is deactivated — activate it instead (that sets a new password)'); }
        wp_set_password(wcp_password($in), $u->ID);
        wcp_end_sessions($u->ID);
        wcp_out(array('user' => wcp_row(get_userdata($u->ID))));

    case 'set-role':
        $u = wcp_user($in);
        $role = wcp_role($in);
        if (get_user_meta($u->ID, WCP_PREV_ROLES, true)) { wcp_fail('this user is deactivated — activate it first'); }
        if ($role !== 'administrator' && wcp_last_admin($u)) { wcp_fail('this is the only administrator — make another user an administrator first'); }
        $u->set_role($role);
        wcp_out(array('user' => wcp_row(get_userdata($u->ID))));

    case 'deactivate':
        $u = wcp_user($in);
        if (get_user_meta($u->ID, WCP_PREV_ROLES, true)) { wcp_out(array('user' => wcp_row($u))); }
        if (wcp_last_admin($u)) { wcp_fail('this is the only administrator — it cannot be deactivated'); }
        update_user_meta($u->ID, WCP_PREV_ROLES, $u->roles ? implode(',', $u->roles) : 'none');
        $u->set_role('');
        wp_set_password(wp_generate_password(40, true, true), $u->ID);
        wcp_end_sessions($u->ID);
        wcp_out(array('user' => wcp_row(get_userdata($u->ID))));

    case 'activate':
        $u = wcp_user($in);
        $prev = get_user_meta($u->ID, WCP_PREV_ROLES, true);
        if (!is_string($prev) || $prev === '') { wcp_fail('this user is not deactivated'); }
        $pw = wcp_password($in);
        $u->set_role('');
        foreach (explode(',', $prev) as $r) { if ($r !== 'none' && wp_roles()->is_role($r)) { $u->add_role($r); } }
        delete_user_meta($u->ID, WCP_PREV_ROLES);
        wp_set_password($pw, $u->ID);
        wcp_out(array('user' => wcp_row(get_userdata($u->ID))));

    case 'delete':
        require_once ABSPATH . 'wp-admin/includes/user.php';
        $u = wcp_user($in);
        if (wcp_last_admin($u)) { wcp_fail('this is the only administrator — it cannot be deleted'); }
        $to = get_userdata(isset($in['reassign']) ? (int) $in['reassign'] : 0);
        if (!$to || (int) $to->ID === (int) $u->ID) { wcp_fail('choose another user to take over this user\'s posts'); }
        if (!wp_delete_user($u->ID, $to->ID)) { wcp_fail('WordPress refused to delete the user'); }
        wcp_out(array('deleted' => (int) $u->ID, 'reassigned_to' => (int) $to->ID));

    default:
        wcp_fail('unknown action: ' . $action);
}

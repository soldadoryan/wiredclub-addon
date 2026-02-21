<?php
/**
 * Plugin Name: WiredClub Addon
 * Description: Modificações necessárias para o portal Wired Club.
 * Version: 1.4.0
 * Author: an4log (WiredClub Team)
 */

if (!defined('ABSPATH')) {
    exit;
}

// ==============================
// JWT Authentication
// ==============================

/**
 * Verifica um token JWT do header Authorization: Bearer.
 * Retorna o payload decodificado ou null em caso de falha.
 */
function wiredclub_verify_jwt(): ?array {
    $auth_header = '';

    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
    } elseif (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }

    if (!preg_match('/^Bearer\s+(.+)$/i', $auth_header, $matches)) {
        return null;
    }

    $token = $matches[1];
    $secret = defined('WIREDCLUB_JWT_SECRET') ? WIREDCLUB_JWT_SECRET : '';

    if (empty($secret)) {
        return null;
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }

    [$header_b64, $payload_b64, $signature_b64] = $parts;

    // Verificar assinatura (HS256)
    $expected_sig = hash_hmac('sha256', "$header_b64.$payload_b64", $secret, true);
    $expected_sig_b64 = rtrim(strtr(base64_encode($expected_sig), '+/', '-_'), '=');

    if (!hash_equals($expected_sig_b64, $signature_b64)) {
        return null;
    }

    // Decodificar payload
    $payload_json = base64_decode(strtr($payload_b64, '-_', '+/'));
    $payload = json_decode($payload_json, true);

    if (!$payload || !is_array($payload)) {
        return null;
    }

    // Verificar expiração
    if (isset($payload['exp']) && time() > $payload['exp']) {
        return null;
    }

    return $payload;
}

/**
 * Permission callback que exige um JWT válido.
 * Extrai o nickname do token e injeta no request.
 */
function wiredclub_jwt_permission(WP_REST_Request $request) {
    $payload = wiredclub_verify_jwt();

    if (!$payload || empty($payload['nickname'])) {
        return new WP_Error(
            'rest_forbidden',
            'Token de autenticação inválido ou expirado.',
            ['status' => 401]
        );
    }

    if (wiredclub_is_banned($payload['nickname'])) {
        return new WP_Error(
            'rest_forbidden',
            'Este nickname está banido.',
            ['status' => 403]
        );
    }

    // Anexar o nickname verificado ao request
    $request->set_param('_jwt_nickname', $payload['nickname']);
    $request->set_param('_jwt_wp_user_id', $payload['wpUserId'] ?? 0);

    return true;
}

// ==============================
// Ativação: criar tabela de bans
// ==============================

register_activation_hook(__FILE__, function () {
    global $wpdb;
    $charset = $wpdb->get_charset_collate();
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    // Tabela de bans
    $bans_table = $wpdb->prefix . 'wiredclub_bans';
    dbDelta("CREATE TABLE IF NOT EXISTS $bans_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        nickname VARCHAR(100) NOT NULL,
        reason VARCHAR(255) DEFAULT '',
        banned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        banned_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (id),
        UNIQUE KEY nickname (nickname)
    ) $charset;");

    // Tabela de likes
    $likes_table = $wpdb->prefix . 'wiredclub_likes';
    dbDelta("CREATE TABLE IF NOT EXISTS $likes_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        post_id BIGINT UNSIGNED NOT NULL,
        nickname VARCHAR(100) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY post_nickname (post_id, nickname)
    ) $charset;");

    // Tabela de emblemas
    $badges_table = $wpdb->prefix . 'wiredclub_badges';
    dbDelta("CREATE TABLE IF NOT EXISTS $badges_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        badge_id VARCHAR(100) NOT NULL,
        name VARCHAR(255) NOT NULL,
        attachment_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY badge_id (badge_id)
    ) $charset;");

    // Tabela de relação jogador-emblema
    $player_badges_table = $wpdb->prefix . 'wiredclub_player_badges';
    dbDelta("CREATE TABLE IF NOT EXISTS $player_badges_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        badge_id VARCHAR(100) NOT NULL,
        is_featured TINYINT(1) NOT NULL DEFAULT 0,
        granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY user_badge (user_id, badge_id),
        KEY badge_id (badge_id)
    ) $charset;");

    // Tabela de votos em comentários
    $comment_votes_table = $wpdb->prefix . 'wiredclub_comment_votes';
    dbDelta("CREATE TABLE IF NOT EXISTS $comment_votes_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        comment_id BIGINT UNSIGNED NOT NULL,
        nickname VARCHAR(100) NOT NULL,
        vote TINYINT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY comment_nickname (comment_id, nickname)
    ) $charset;");

    // Tabela de webhooks do Discord
    $webhooks_table = $wpdb->prefix . 'wiredclub_webhooks';
    dbDelta("CREATE TABLE IF NOT EXISTS $webhooks_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        category_id BIGINT UNSIGNED NOT NULL,
        webhook_url VARCHAR(500) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY category_id (category_id)
    ) $charset;");
});

// ==============================
// REST API
// ==============================

add_action('rest_api_init', function () {
    // Campos de engajamento nos posts
    register_rest_field('post', 'likes_count', [
        'get_callback' => function ($post) {
            return wiredclub_get_likes_count($post['id']);
        },
        'schema' => ['type' => 'integer'],
    ]);

    register_rest_field('post', 'comments_count', [
        'get_callback' => function ($post) {
            return (int) get_comments([
                'post_id' => $post['id'],
                'status'  => 'approve',
                'count'   => true,
            ]);
        },
        'schema' => ['type' => 'integer'],
    ]);

    register_rest_field('post', 'shares_count', [
        'get_callback' => function ($post) {
            return (int) get_post_meta($post['id'], 'wiredclub_shares_count', true);
        },
        'schema' => ['type' => 'integer'],
    ]);

    // Endpoint de busca de usuário por login exato
    register_rest_route('wp/v2', '/wiredclub/user/find', [
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'wiredclub_find_user_by_login',
        'permission_callback' => '__return_true',
        'args'                => [
            'nickname' => [
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Endpoint de verificação de admin
    register_rest_route('wp/v2', '/wiredclub/user/is-admin', [
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'wiredclub_check_is_admin',
        'permission_callback' => '__return_true',
        'args'                => [
            'nickname' => [
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Endpoint de verificação de ban
    register_rest_route('wp/v2', '/wiredclub/ban/check', [
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'wiredclub_check_ban',
        'permission_callback' => '__return_true',
        'args'                => [
            'nickname' => [
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Endpoints de like
    register_rest_route('wp/v2', '/wiredclub/like', [
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => 'wiredclub_toggle_like',
        'permission_callback' => 'wiredclub_jwt_permission',
        'args'                => [
            'post' => [
                'required'          => true,
                'type'              => 'integer',
                'sanitize_callback' => 'absint',
            ],
        ],
    ]);

    register_rest_route('wp/v2', '/wiredclub/like/check', [
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'wiredclub_check_like',
        'permission_callback' => '__return_true',
        'args'                => [
            'post' => [
                'required'          => true,
                'type'              => 'integer',
                'sanitize_callback' => 'absint',
            ],
            'nickname' => [
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Endpoint de share
    register_rest_route('wp/v2', '/wiredclub/share', [
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => 'wiredclub_increment_share',
        'permission_callback' => '__return_true',
        'args'                => [
            'post' => [
                'required'          => true,
                'type'              => 'integer',
                'sanitize_callback' => 'absint',
            ],
        ],
    ]);

    // Comment vote endpoints
    register_rest_route('wp/v2', '/wiredclub/comment/vote', [
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => 'wiredclub_vote_comment',
        'permission_callback' => 'wiredclub_jwt_permission',
        'args'                => [
            'comment_id' => [
                'required'          => true,
                'type'              => 'integer',
                'sanitize_callback' => 'absint',
            ],
            'vote' => [
                'required'          => true,
                'type'              => 'integer',
                'validate_callback' => function ($value) {
                    return in_array((int) $value, [1, -1], true);
                },
            ],
        ],
    ]);

    register_rest_route('wp/v2', '/wiredclub/comment/votes', [
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'wiredclub_get_comment_votes',
        'permission_callback' => '__return_true',
        'args'                => [
            'comment_id' => [
                'required'          => true,
                'type'              => 'integer',
                'sanitize_callback' => 'absint',
            ],
            'nickname' => [
                'required'          => false,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Player endpoints
    register_rest_route('wp/v2', '/wiredclub/players', [
        [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => 'wiredclub_register_player',
            'permission_callback' => '__return_true',
            'args'                => [
                'nickname' => [
                    'required'          => true,
                    'type'              => 'string',
                    'sanitize_callback' => 'sanitize_user',
                ],
            ],
        ],
        [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => 'wiredclub_list_players',
            'permission_callback' => '__return_true',
            'args'                => [
                'per_page' => [
                    'required'          => false,
                    'type'              => 'integer',
                    'default'           => 20,
                    'sanitize_callback' => 'absint',
                ],
                'page' => [
                    'required'          => false,
                    'type'              => 'integer',
                    'default'           => 1,
                    'sanitize_callback' => 'absint',
                ],
                'search' => [
                    'required'          => false,
                    'type'              => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
            ],
        ],
    ]);

    register_rest_route('wp/v2', '/wiredclub/players/(?P<nickname>[a-zA-Z0-9_\-\.]+)', [
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'wiredclub_get_player',
        'permission_callback' => '__return_true',
        'args'                => [
            'nickname' => [
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Endpoint para atualizar emblema em destaque
    register_rest_route('wp/v2', '/wiredclub/players/featured-badge', [
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => 'wiredclub_update_featured_badge',
        'permission_callback' => 'wiredclub_jwt_permission',
        'args'                => [
            'badge' => [
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
            ],
        ],
    ]);

    // Comments endpoints
    register_rest_route('wp/v2', '/wiredclub/comments', [
        [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => 'wiredclub_get_comments',
            'permission_callback' => '__return_true',
            'args'                => [
                'post' => [
                    'required'          => true,
                    'type'              => 'integer',
                    'sanitize_callback' => 'absint',
                    'description'       => 'ID do post.',
                ],
                'per_page' => [
                    'required'          => false,
                    'type'              => 'integer',
                    'default'           => 100,
                    'sanitize_callback' => 'absint',
                ],
                'page' => [
                    'required'          => false,
                    'type'              => 'integer',
                    'default'           => 1,
                    'sanitize_callback' => 'absint',
                ],
                'order' => [
                    'required'          => false,
                    'type'              => 'string',
                    'default'           => 'desc',
                    'enum'              => ['asc', 'desc'],
                ],
            ],
        ],
        [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => 'wiredclub_create_comment',
            'permission_callback' => 'wiredclub_jwt_permission',
            'args'                => [
                'post' => [
                    'required'          => true,
                    'type'              => 'integer',
                    'sanitize_callback' => 'absint',
                    'description'       => 'ID do post.',
                ],
                'content' => [
                    'required'          => true,
                    'type'              => 'string',
                    'sanitize_callback' => 'wp_kses_post',
                    'description'       => 'Conteúdo do comentário.',
                ],
                'parent' => [
                    'required'          => false,
                    'type'              => 'integer',
                    'default'           => 0,
                    'sanitize_callback' => 'absint',
                    'description'       => 'ID do comentário pai (resposta).',
                ],
            ],
        ],
    ]);
});

// ==============================
// Players (Subscribers)
// ==============================

/**
 * POST /wp-json/wp/v2/wiredclub/players
 * Cadastra um usuário como Assinante (subscriber). Sem senha/email real.
 */
function wiredclub_register_player(WP_REST_Request $request): WP_REST_Response {
    $nickname = trim($request->get_param('nickname'));

    if (empty($nickname)) {
        return new WP_REST_Response([
            'code'    => 'empty_nickname',
            'message' => 'O nickname é obrigatório.',
        ], 400);
    }

    // Verificar se já existe
    $existing = get_user_by('login', $nickname);
    if ($existing) {
        return new WP_REST_Response([
            'code'    => 'nickname_exists',
            'message' => 'Este nickname já está cadastrado.',
        ], 409);
    }

    $fake_email = sanitize_email(strtolower($nickname) . '@habbo.wiredclub.com');
    $random_password = wp_generate_password(32, true, true);

    $user_id = wp_insert_user([
        'user_login'   => $nickname,
        'user_pass'    => $random_password,
        'user_email'   => $fake_email,
        'display_name' => $nickname,
        'role'         => 'subscriber',
    ]);

    if (is_wp_error($user_id)) {
        return new WP_REST_Response([
            'code'    => 'registration_failed',
            'message' => $user_id->get_error_message(),
        ], 500);
    }

    // Dar emblema padrão
    wiredclub_give_badge($user_id, 'emb_wiredclub');
    wiredclub_set_featured_badge($user_id, 'emb_wiredclub');

    return new WP_REST_Response([
        'id'       => $user_id,
        'nickname' => $nickname,
        'message'  => 'Jogador cadastrado com sucesso.',
    ], 201);
}

/**
 * GET /wp-json/wp/v2/wiredclub/players?per_page=20&page=1&search=termo
 * Lista todos os jogadores (subscribers).
 */
function wiredclub_list_players(WP_REST_Request $request): WP_REST_Response {
    $per_page = $request->get_param('per_page');
    $page     = $request->get_param('page');
    $search   = $request->get_param('search');

    $args = [
        'role'    => 'subscriber',
        'number'  => $per_page,
        'paged'   => $page,
        'orderby' => 'registered',
        'order'   => 'DESC',
    ];

    if (!empty($search)) {
        $args['search']         = '*' . $search . '*';
        $args['search_columns'] = ['user_login', 'display_name'];
    }

    $query = new WP_User_Query($args);
    $users = $query->get_results();
    $total = $query->get_total();

    $data = array_map(function ($user) {
        return wiredclub_format_player($user);
    }, $users);

    $response = new WP_REST_Response($data, 200);
    $response->header('X-WP-Total', $total);
    $response->header('X-WP-TotalPages', (int) ceil($total / $per_page));

    return $response;
}

/**
 * GET /wp-json/wp/v2/wiredclub/players/{nickname}
 * Busca um jogador pelo nickname, incluindo campos ACF.
 */
function wiredclub_get_player(WP_REST_Request $request): WP_REST_Response {
    $nickname = $request->get_param('nickname');
    $user     = get_user_by('login', $nickname);

    if (!$user) {
        return new WP_REST_Response([
            'code'    => 'player_not_found',
            'message' => 'Jogador não encontrado.',
        ], 404);
    }

    return new WP_REST_Response(wiredclub_format_player($user), 200);
}

/**
 * Formata os dados de um jogador, incluindo campos ACF.
 */
function wiredclub_format_player(WP_User $user): array {
    $data = [
        'id'            => $user->ID,
        'nickname'      => $user->user_login,
        'display_name'  => $user->display_name,
        'registered'    => mysql_to_rfc3339($user->user_registered),
        'avatar'        => 'https://www.habbo.com.br/habbo-imaging/avatarimage?img_format=png&user=' . urlencode($user->user_login) . '&direction=2&head_direction=2&size=l',
        'is_admin'      => in_array('administrator', $user->roles, true),
        'is_banned'     => wiredclub_is_banned($user->user_login),
    ];

    // Emblemas do jogador (da tabela de relação)
    $badges = wiredclub_get_player_badges($user->ID);
    $data['badges'] = $badges;

    $featured = '';
    foreach ($badges as $b) {
        if (!empty($b['is_featured'])) {
            $featured = $b['badge_id'];
            break;
        }
    }
    $data['featured_badge'] = $featured;

    // Incluir campos ACF extras (se ACF estiver ativo)
    if (function_exists('get_fields')) {
        $acf_fields = get_fields('user_' . $user->ID);
        if (!empty($acf_fields) && is_array($acf_fields)) {
            // Remover campos de emblemas migrados
            unset($acf_fields['emblemas'], $acf_fields['emblema_em_destaque']);
            $data['acf'] = !empty($acf_fields) ? $acf_fields : (object) [];
        } else {
            $data['acf'] = (object) [];
        }
    }

    return $data;
}

/**
 * POST /wp-json/wp/v2/wiredclub/players/featured-badge
 * Atualiza o emblema em destaque do jogador autenticado.
 */
function wiredclub_update_featured_badge(WP_REST_Request $request): WP_REST_Response {
    $wp_user_id = (int) $request->get_param('_jwt_wp_user_id');
    $badge      = $request->get_param('badge');

    if (!$wp_user_id) {
        return new WP_REST_Response([
            'code'    => 'invalid_user',
            'message' => 'Usuário não encontrado.',
        ], 400);
    }

    $success = wiredclub_set_featured_badge($wp_user_id, $badge);

    if (!$success) {
        return new WP_REST_Response([
            'code'    => 'invalid_badge',
            'message' => 'Você não possui este emblema.',
        ], 400);
    }

    return new WP_REST_Response([
        'success'        => true,
        'featured_badge' => $badge,
    ], 200);
}

/**
 * GET /wp-json/wp/v2/wiredclub/comments?post={id}
 */
function wiredclub_get_comments(WP_REST_Request $request): WP_REST_Response {
    $post_id  = $request->get_param('post');
    $per_page = $request->get_param('per_page');
    $page     = $request->get_param('page');
    $order    = $request->get_param('order');

    $post = get_post($post_id);
    if (!$post || $post->post_status !== 'publish') {
        return new WP_REST_Response([
            'code'    => 'invalid_post',
            'message' => 'Post não encontrado.',
        ], 404);
    }

    $args = [
        'post_id' => $post_id,
        'status'  => 'approve',
        'number'  => $per_page,
        'offset'  => ($page - 1) * $per_page,
        'order'   => $order,
    ];

    $comments    = get_comments($args);
    $total       = (int) get_comments(array_merge($args, ['count' => true, 'number' => 0, 'offset' => 0]));
    $total_pages = (int) ceil($total / $per_page);

    $data = array_map('wiredclub_format_comment', $comments);

    $response = new WP_REST_Response($data, 200);
    $response->header('X-WP-Total', $total);
    $response->header('X-WP-TotalPages', $total_pages);

    return $response;
}

/**
 * POST /wp-json/wp/v2/wiredclub/comments
 */
function wiredclub_create_comment(WP_REST_Request $request): WP_REST_Response {
    $post_id     = $request->get_param('post');
    $author_name = $request->get_param('_jwt_nickname');
    $content     = $request->get_param('content');
    $parent      = $request->get_param('parent') ?: 0;

    // Verificar ban (já checado no permission_callback, mas mantém por segurança)
    if (wiredclub_is_banned($author_name)) {
        return new WP_REST_Response([
            'code'    => 'author_banned',
            'message' => 'Este nickname está banido de comentar.',
        ], 403);
    }

    $post = get_post($post_id);
    if (!$post || $post->post_status !== 'publish') {
        return new WP_REST_Response([
            'code'    => 'invalid_post',
            'message' => 'Post não encontrado.',
        ], 404);
    }

    if (!comments_open($post_id)) {
        return new WP_REST_Response([
            'code'    => 'comments_closed',
            'message' => 'Comentários estão fechados para este post.',
        ], 403);
    }

    if (empty(trim($content))) {
        return new WP_REST_Response([
            'code'    => 'empty_content',
            'message' => 'O conteúdo do comentário não pode ser vazio.',
        ], 400);
    }

    // Rate limiting simples por IP (1 comentário a cada 15 segundos)
    $ip = wiredclub_get_client_ip();
    $transient_key = 'wc_rate_' . md5($ip);
    if (get_transient($transient_key)) {
        return new WP_REST_Response([
            'code'    => 'rate_limited',
            'message' => 'Aguarde alguns segundos antes de comentar novamente.',
        ], 429);
    }

    // Checar se comentário duplicado
    $duplicate = get_comments([
        'post_id'      => $post_id,
        'author'       => $author_name,
        'search'       => $content,
        'count'        => true,
        'date_query'   => [
            ['after' => '5 minutes ago'],
        ],
    ]);

    if ($duplicate > 0) {
        return new WP_REST_Response([
            'code'    => 'duplicate_comment',
            'message' => 'Comentário duplicado detectado.',
        ], 409);
    }

    $author_email = sanitize_email(strtolower($author_name) . '@habbo.wiredclub.com');

    $comment_data = [
        'comment_post_ID'      => $post_id,
        'comment_author'       => $author_name,
        'comment_author_email' => $author_email,
        'comment_content'      => $content,
        'comment_parent'       => $parent,
        'comment_author_IP'    => $ip,
        'comment_agent'        => sanitize_text_field($request->get_header('user_agent') ?? ''),
        'comment_approved'     => 1,
    ];

    $comment_id = wp_insert_comment($comment_data);

    if (!$comment_id) {
        return new WP_REST_Response([
            'code'    => 'comment_failed',
            'message' => 'Erro ao salvar o comentário.',
        ], 500);
    }

    set_transient($transient_key, true, 15);

    $comment = get_comment($comment_id);

    $total_comments = (int) get_comments([
        'post_id' => $post_id,
        'status'  => 'approve',
        'count'   => true,
    ]);

    $response_data = wiredclub_format_comment($comment);
    $response_data['total_comments'] = $total_comments;

    return new WP_REST_Response($response_data, 201);
}

/**
 * Formata um comentário no padrão da WP REST API.
 */
function wiredclub_format_comment(WP_Comment $comment): array {
    $is_staff = false;
    $user = null;
    $author_email = $comment->comment_author_email;

    if ($author_email) {
        $user = get_user_by('email', $author_email);
        if ($user && in_array('administrator', $user->roles, true)) {
            $is_staff = true;
        }
    }

    if (!$user) {
        $user = get_user_by('login', $comment->comment_author);
        if ($user && in_array('administrator', $user->roles, true)) {
            $is_staff = true;
        }
    }

    // Buscar emblema em destaque do autor
    $featured_badge = null;
    if ($user) {
        global $wpdb;
        $pb_table = $wpdb->prefix . 'wiredclub_player_badges';
        $b_table  = $wpdb->prefix . 'wiredclub_badges';

        $badge = $wpdb->get_row($wpdb->prepare(
            "SELECT b.badge_id, b.name, b.attachment_id
             FROM $pb_table pb
             INNER JOIN $b_table b ON b.badge_id = pb.badge_id
             WHERE pb.user_id = %d AND pb.is_featured = 1
             LIMIT 1",
            $user->ID
        ), ARRAY_A);

        if ($badge) {
            $featured_badge = [
                'badge_id'  => $badge['badge_id'],
                'name'      => $badge['name'],
                'image_url' => $badge['attachment_id'] ? wp_get_attachment_url((int) $badge['attachment_id']) : '',
            ];
        }
    }

    $votes = wiredclub_get_comment_vote_counts((int) $comment->comment_ID);

    return [
        'id'              => (int) $comment->comment_ID,
        'post'            => (int) $comment->comment_post_ID,
        'parent'          => (int) $comment->comment_parent,
        'author'          => (int) $comment->user_id,
        'author_name'     => $comment->comment_author,
        'author_avatar'   => 'https://www.habbo.com.br/habbo-imaging/avatarimage?img_format=png&user=' . urlencode($comment->comment_author) . '&direction=2&head_direction=2&size=l',
        'is_staff'        => $is_staff,
        'featured_badge'  => $featured_badge,
        'date'            => mysql_to_rfc3339($comment->comment_date),
        'date_gmt'        => mysql_to_rfc3339($comment->comment_date_gmt),
        'content'         => [
            'rendered' => apply_filters('comment_text', $comment->comment_content, $comment, []),
        ],
        'likes'           => $votes['likes'],
        'dislikes'        => $votes['dislikes'],
        'status'          => wp_get_comment_status($comment),
        'type'            => $comment->comment_type ?: 'comment',
    ];
}

/**
 * Obtém o IP real do cliente.
 */
function wiredclub_get_client_ip(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', sanitize_text_field($_SERVER['HTTP_X_FORWARDED_FOR']));
        return trim($ips[0]);
    }
    return sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
}

// ==============================
// Comment Votes
// ==============================

function wiredclub_get_comment_vote_counts(int $comment_id): array {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_comment_votes';

    $likes = (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE comment_id = %d AND vote = 1",
        $comment_id
    ));

    $dislikes = (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE comment_id = %d AND vote = -1",
        $comment_id
    ));

    return ['likes' => $likes, 'dislikes' => $dislikes];
}

function wiredclub_vote_comment(WP_REST_Request $request): WP_REST_Response {
    global $wpdb;
    $table      = $wpdb->prefix . 'wiredclub_comment_votes';
    $comment_id = $request->get_param('comment_id');
    $nickname   = strtolower($request->get_param('_jwt_nickname'));
    $vote       = (int) $request->get_param('vote');

    $comment = get_comment($comment_id);
    if (!$comment) {
        return new WP_REST_Response(['code' => 'invalid_comment', 'message' => 'Comentário não encontrado.'], 404);
    }

    $existing = $wpdb->get_row($wpdb->prepare(
        "SELECT id, vote FROM $table WHERE comment_id = %d AND nickname = %s",
        $comment_id,
        $nickname
    ));

    $user_vote = 0;

    if ($existing) {
        if ((int) $existing->vote === $vote) {
            // Same vote = remove (toggle off)
            $wpdb->delete($table, ['id' => $existing->id]);
            $user_vote = 0;
        } else {
            // Different vote = update
            $wpdb->update($table, ['vote' => $vote], ['id' => $existing->id]);
            $user_vote = $vote;
        }
    } else {
        $wpdb->insert($table, [
            'comment_id' => $comment_id,
            'nickname'   => $nickname,
            'vote'       => $vote,
            'created_at' => current_time('mysql'),
        ]);
        $user_vote = $vote;
    }

    $counts = wiredclub_get_comment_vote_counts($comment_id);

    return new WP_REST_Response([
        'user_vote' => $user_vote,
        'likes'     => $counts['likes'],
        'dislikes'  => $counts['dislikes'],
    ], 200);
}

function wiredclub_get_comment_votes(WP_REST_Request $request): WP_REST_Response {
    global $wpdb;
    $table      = $wpdb->prefix . 'wiredclub_comment_votes';
    $comment_id = $request->get_param('comment_id');
    $nickname   = $request->get_param('nickname');

    $counts = wiredclub_get_comment_vote_counts($comment_id);

    $user_vote = 0;
    if ($nickname) {
        $vote = $wpdb->get_var($wpdb->prepare(
            "SELECT vote FROM $table WHERE comment_id = %d AND nickname = %s",
            $comment_id,
            strtolower($nickname)
        ));
        if ($vote !== null) {
            $user_vote = (int) $vote;
        }
    }

    return new WP_REST_Response([
        'user_vote' => $user_vote,
        'likes'     => $counts['likes'],
        'dislikes'  => $counts['dislikes'],
    ], 200);
}

// ==============================
// Engagement - Likes & Shares
// ==============================

function wiredclub_get_likes_count(int $post_id): int {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_likes';
    return (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE post_id = %d",
        $post_id
    ));
}

function wiredclub_toggle_like(WP_REST_Request $request): WP_REST_Response {
    global $wpdb;
    $table    = $wpdb->prefix . 'wiredclub_likes';
    $post_id  = $request->get_param('post');
    $nickname = $request->get_param('_jwt_nickname');

    $post = get_post($post_id);
    if (!$post || $post->post_status !== 'publish') {
        return new WP_REST_Response(['code' => 'invalid_post', 'message' => 'Post não encontrado.'], 404);
    }

    $existing = $wpdb->get_var($wpdb->prepare(
        "SELECT id FROM $table WHERE post_id = %d AND nickname = %s",
        $post_id,
        strtolower($nickname)
    ));

    if ($existing) {
        $wpdb->delete($table, ['id' => $existing]);
        $liked = false;
    } else {
        $wpdb->insert($table, [
            'post_id'    => $post_id,
            'nickname'   => strtolower($nickname),
            'created_at' => current_time('mysql'),
        ]);
        $liked = true;
    }

    return new WP_REST_Response([
        'liked'       => $liked,
        'likes_count' => wiredclub_get_likes_count($post_id),
    ], 200);
}

function wiredclub_check_like(WP_REST_Request $request): WP_REST_Response {
    global $wpdb;
    $table    = $wpdb->prefix . 'wiredclub_likes';
    $post_id  = $request->get_param('post');
    $nickname = $request->get_param('nickname');

    $exists = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE post_id = %d AND nickname = %s",
        $post_id,
        strtolower($nickname)
    ));

    return new WP_REST_Response(['liked' => (int) $exists > 0], 200);
}

function wiredclub_increment_share(WP_REST_Request $request): WP_REST_Response {
    $post_id = $request->get_param('post');

    $post = get_post($post_id);
    if (!$post || $post->post_status !== 'publish') {
        return new WP_REST_Response(['code' => 'invalid_post', 'message' => 'Post não encontrado.'], 404);
    }

    $current = (int) get_post_meta($post_id, 'wiredclub_shares_count', true);
    update_post_meta($post_id, 'wiredclub_shares_count', $current + 1);

    return new WP_REST_Response(['shares_count' => $current + 1], 200);
}

// ==============================
// Sistema de Ban - Helpers
// ==============================

function wiredclub_find_user_by_login(WP_REST_Request $request): WP_REST_Response {
    $nickname = $request->get_param('nickname');
    $user = get_user_by('login', $nickname);

    if (!$user) {
        return new WP_REST_Response(['found' => false], 200);
    }

    $is_admin = in_array('administrator', $user->roles, true);

    return new WP_REST_Response([
        'found'    => true,
        'id'       => $user->ID,
        'is_admin' => $is_admin,
    ], 200);
}

function wiredclub_check_is_admin(WP_REST_Request $request): WP_REST_Response {
    $nickname = $request->get_param('nickname');
    $is_admin = false;

    // Verificar por email (mesmo padrão dos comentários)
    $author_email = sanitize_email(strtolower($nickname) . '@habbo.wiredclub.com');
    $user = get_user_by('email', $author_email);
    if ($user && in_array('administrator', $user->roles, true)) {
        $is_admin = true;
    }

    // Fallback: verificar por login
    if (!$is_admin) {
        $user = get_user_by('login', $nickname);
        if ($user && in_array('administrator', $user->roles, true)) {
            $is_admin = true;
        }
    }

    return new WP_REST_Response(['is_admin' => $is_admin], 200);
}

function wiredclub_check_ban(WP_REST_Request $request): WP_REST_Response {
    $nickname = $request->get_param('nickname');
    $banned = wiredclub_is_banned($nickname);

    return new WP_REST_Response(['banned' => $banned], 200);
}

function wiredclub_is_banned(string $nickname): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_bans';
    $result = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE nickname = %s",
        strtolower($nickname)
    ));
    return (int) $result > 0;
}

function wiredclub_ban_nickname(string $nickname, string $reason = '', int $banned_by = 0): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_bans';
    $result = $wpdb->replace($table, [
        'nickname'  => strtolower($nickname),
        'reason'    => sanitize_text_field($reason),
        'banned_at' => current_time('mysql'),
        'banned_by' => $banned_by,
    ]);
    return $result !== false;
}

function wiredclub_unban_nickname(string $nickname): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_bans';
    $result = $wpdb->delete($table, ['nickname' => strtolower($nickname)]);
    return $result !== false;
}

// ==============================
// Player Badges - Helpers
// ==============================

function wiredclub_give_badge(int $user_id, string $badge_id): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_player_badges';
    $result = $wpdb->replace($table, [
        'user_id'    => $user_id,
        'badge_id'   => $badge_id,
        'granted_at' => current_time('mysql'),
    ]);
    return $result !== false;
}

function wiredclub_revoke_badge(int $user_id, string $badge_id): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_player_badges';

    // Se era o destaque, promover outro
    $was_featured = (bool) $wpdb->get_var($wpdb->prepare(
        "SELECT is_featured FROM $table WHERE user_id = %d AND badge_id = %s",
        $user_id, $badge_id
    ));

    $wpdb->delete($table, ['user_id' => $user_id, 'badge_id' => $badge_id]);

    if ($was_featured) {
        // Promover o primeiro emblema restante
        $first = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table WHERE user_id = %d ORDER BY granted_at ASC LIMIT 1",
            $user_id
        ));
        if ($first) {
            $wpdb->update($table, ['is_featured' => 1], ['id' => $first]);
        }
    }

    return true;
}

function wiredclub_get_player_badges(int $user_id): array {
    global $wpdb;
    $pb_table = $wpdb->prefix . 'wiredclub_player_badges';
    $b_table  = $wpdb->prefix . 'wiredclub_badges';

    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT b.badge_id, b.name, b.attachment_id, pb.is_featured
         FROM $pb_table pb
         INNER JOIN $b_table b ON b.badge_id = pb.badge_id
         WHERE pb.user_id = %d
         ORDER BY pb.granted_at ASC",
        $user_id
    ), ARRAY_A) ?: [];

    // Adicionar URL da imagem
    foreach ($rows as &$row) {
        $row['image_url'] = $row['attachment_id'] ? wp_get_attachment_url((int) $row['attachment_id']) : '';
    }

    return $rows;
}

function wiredclub_set_featured_badge(int $user_id, string $badge_id): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_player_badges';

    // Verificar se o usuário possui o emblema
    $exists = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE user_id = %d AND badge_id = %s",
        $user_id, $badge_id
    ));

    if (!$exists) return false;

    // Remover destaque atual
    $wpdb->update($table, ['is_featured' => 0], ['user_id' => $user_id, 'is_featured' => 1]);
    // Definir novo destaque
    $wpdb->update($table, ['is_featured' => 1], ['user_id' => $user_id, 'badge_id' => $badge_id]);

    return true;
}

function wiredclub_give_badge_to_all(string $badge_id): int {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_player_badges';

    $users = get_users(['role' => 'subscriber', 'fields' => 'ID']);
    $count = 0;

    foreach ($users as $user_id) {
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE user_id = %d AND badge_id = %s",
            $user_id, $badge_id
        ));

        if (!$exists) {
            wiredclub_give_badge((int) $user_id, $badge_id);
            $count++;
        }
    }

    return $count;
}

function wiredclub_revoke_badge_from_all(string $badge_id): int {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_player_badges';

    // Get all users who have this badge
    $user_ids = $wpdb->get_col($wpdb->prepare(
        "SELECT user_id FROM $table WHERE badge_id = %s",
        $badge_id
    ));

    $count = 0;
    foreach ($user_ids as $user_id) {
        wiredclub_revoke_badge((int) $user_id, $badge_id);
        $count++;
    }

    return $count;
}

function wiredclub_player_has_badge(int $user_id, string $badge_id): bool {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_player_badges';
    return (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE user_id = %d AND badge_id = %s",
        $user_id, $badge_id
    )) > 0;
}

// ==============================
// Admin - User Search AJAX
// ==============================

add_action('wp_ajax_wiredclub_search_users', function () {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Sem permissão.', 403);
    }

    $term = sanitize_text_field($_GET['term'] ?? '');
    if (strlen($term) < 2) {
        wp_send_json([]);
    }

    $users = get_users([
        'search'         => '*' . $term . '*',
        'search_columns' => ['user_login', 'display_name'],
        'number'         => 10,
        'orderby'        => 'user_login',
        'order'          => 'ASC',
    ]);

    $results = [];
    foreach ($users as $user) {
        $results[] = [
            'label' => $user->user_login,
            'value' => $user->user_login,
        ];
    }

    wp_send_json($results);
});

add_action('admin_enqueue_scripts', function ($hook) {
    if ($hook !== 'toplevel_page_wiredclub-addons') {
        return;
    }
    wp_enqueue_script('jquery-ui-autocomplete');
    wp_enqueue_style('wiredclub-admin', false);
    wp_add_inline_style('wiredclub-admin', '
        .wc-nickname-wrap { position: relative; display: inline-block; }
        .wc-nickname-wrap .wc-nickname-results {
            position: absolute; top: 100%; left: 0; right: 0; z-index: 9999;
            background: #fff; border: 1px solid #8c8f94; border-top: none;
            max-height: 200px; overflow-y: auto; display: none;
        }
        .wc-nickname-wrap .wc-nickname-results .wc-nick-item {
            padding: 6px 10px; cursor: pointer; display: flex; align-items: center; gap: 8px;
        }
        .wc-nickname-wrap .wc-nickname-results .wc-nick-item:hover,
        .wc-nickname-wrap .wc-nickname-results .wc-nick-item.active {
            background: #2271b1; color: #fff;
        }
        .wc-nickname-wrap .wc-nickname-results .wc-nick-item img {
            width: 24px; height: 24px; border-radius: 2px;
        }
        .wc-nickname-wrap .wc-nick-loading {
            position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
            font-size: 12px; color: #999; display: none;
        }
    ');
});

// ==============================
// Painel Admin - Menu
// ==============================

add_action('admin_menu', function () {
    add_menu_page(
        'WiredClub Addons',
        'WiredClub Addons',
        'manage_options',
        'wiredclub-addons',
        'wiredclub_addons_page',
        'dashicons-admin-generic',
        80
    );
});

// ==============================
// Painel Admin - Página com Tabs
// ==============================

function wiredclub_addons_page(): void {
    $tab     = sanitize_key($_GET['tab'] ?? 'badges');
    $page_url = admin_url('admin.php?page=wiredclub-addons');
    ?>
    <div class="wrap">
        <h1>WiredClub Addons</h1>

        <nav class="nav-tab-wrapper" style="margin-bottom:0;">
            <a href="<?php echo esc_url($page_url . '&tab=badges'); ?>"
               class="nav-tab <?php echo $tab === 'badges' ? 'nav-tab-active' : ''; ?>">
                Emblemas
            </a>
            <a href="<?php echo esc_url($page_url . '&tab=bans'); ?>"
               class="nav-tab <?php echo $tab === 'bans' ? 'nav-tab-active' : ''; ?>">
                Bans
            </a>
            <a href="<?php echo esc_url($page_url . '&tab=webhooks'); ?>"
               class="nav-tab <?php echo $tab === 'webhooks' ? 'nav-tab-active' : ''; ?>">
                Webhooks
            </a>
        </nav>

        <div style="margin-top:20px;">
            <?php
            if ($tab === 'bans') {
                wiredclub_bans_content();
            } elseif ($tab === 'webhooks') {
                wiredclub_webhooks_content();
            } else {
                wiredclub_badges_content();
            }
            ?>
        </div>
    </div>
    <?php
}

// ==============================
// Painel Admin - Conteúdo: Bans
// ==============================

function wiredclub_bans_content(): void {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_bans';

    // Processar ações
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && current_user_can('manage_options')) {
        $action = sanitize_text_field($_POST['wc_action'] ?? '');

        if (!wp_verify_nonce($_POST['_wpnonce'] ?? '', 'wiredclub_bans_action')) {
            wp_die('Ação não autorizada.');
        }

        if ($action === 'ban') {
            $nickname = sanitize_text_field($_POST['nickname'] ?? '');
            $reason   = sanitize_text_field($_POST['reason'] ?? '');
            if ($nickname) {
                wiredclub_ban_nickname($nickname, $reason, get_current_user_id());
                echo '<div class="notice notice-success"><p>Nickname <strong>' . esc_html($nickname) . '</strong> banido com sucesso.</p></div>';
            }
        }

        if ($action === 'unban') {
            $nickname = sanitize_text_field($_POST['nickname'] ?? '');
            if ($nickname) {
                wiredclub_unban_nickname($nickname);
                echo '<div class="notice notice-success"><p>Nickname <strong>' . esc_html($nickname) . '</strong> desbanido com sucesso.</p></div>';
            }
        }
    }

    // Buscar lista de bans
    $bans = $wpdb->get_results("SELECT * FROM $table ORDER BY banned_at DESC");
    ?>
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;margin-top:20px;max-width:500px;">
            <h2 style="margin-top:0;">Banir Nickname</h2>
            <form method="post">
                <?php wp_nonce_field('wiredclub_bans_action'); ?>
                <input type="hidden" name="wc_action" value="ban" />
                <table class="form-table">
                    <tr>
                        <th><label for="nickname">Nickname</label></th>
                        <td>
                            <div class="wc-nickname-wrap">
                                <input type="text" id="nickname" name="nickname" class="regular-text wc-nickname-input" required autocomplete="off" />
                                <span class="wc-nick-loading">buscando...</span>
                                <div class="wc-nickname-results"></div>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="reason">Motivo (opcional)</label></th>
                        <td><input type="text" id="reason" name="reason" class="regular-text" /></td>
                    </tr>
                </table>
                <?php submit_button('Banir', 'primary'); ?>
            </form>
        </div>

        <h2 style="margin-top:30px;">Lista de Banidos (<?php echo count($bans); ?>)</h2>
        <?php if (empty($bans)) : ?>
            <p>Nenhum nickname banido.</p>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Nickname</th>
                        <th>Motivo</th>
                        <th>Banido em</th>
                        <th>Banido por</th>
                        <th>Ação</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($bans as $ban) :
                        $banned_by_user = get_userdata($ban->banned_by);
                        $banned_by_name = $banned_by_user ? $banned_by_user->display_name : '—';
                    ?>
                        <tr>
                            <td><strong><?php echo esc_html($ban->nickname); ?></strong></td>
                            <td><?php echo esc_html($ban->reason ?: '—'); ?></td>
                            <td><?php echo esc_html(date_i18n('d/m/Y H:i', strtotime($ban->banned_at))); ?></td>
                            <td><?php echo esc_html($banned_by_name); ?></td>
                            <td>
                                <form method="post" style="display:inline;">
                                    <?php wp_nonce_field('wiredclub_bans_action'); ?>
                                    <input type="hidden" name="wc_action" value="unban" />
                                    <input type="hidden" name="nickname" value="<?php echo esc_attr($ban->nickname); ?>" />
                                    <button type="submit" class="button button-small" onclick="return confirm('Desbanir <?php echo esc_js($ban->nickname); ?>?')">
                                        Desbanir
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    <?php wiredclub_render_nickname_autocomplete_js(); ?>
    <?php
}

// ==============================
// Painel Admin - Emblemas
// ==============================

function wiredclub_badges_content(): void {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_badges';

    // Enqueue media uploader
    wp_enqueue_media();

    // Processar ações
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && current_user_can('manage_options')) {
        if (!wp_verify_nonce($_POST['_wpnonce'] ?? '', 'wiredclub_badges_action')) {
            wp_die('Ação não autorizada.');
        }

        $action = sanitize_text_field($_POST['wc_action'] ?? '');

        if ($action === 'create') {
            $badge_id      = sanitize_key($_POST['badge_id'] ?? '');
            $name          = sanitize_text_field($_POST['badge_name'] ?? '');
            $attachment_id = absint($_POST['attachment_id'] ?? 0);

            if ($badge_id && $name) {
                $exists = $wpdb->get_var($wpdb->prepare(
                    "SELECT COUNT(*) FROM $table WHERE badge_id = %s",
                    $badge_id
                ));

                if ($exists > 0) {
                    echo '<div class="notice notice-error"><p>O ID <strong>' . esc_html($badge_id) . '</strong> já existe.</p></div>';
                } else {
                    $wpdb->insert($table, [
                        'badge_id'      => $badge_id,
                        'name'          => $name,
                        'attachment_id' => $attachment_id,
                        'created_at'    => current_time('mysql'),
                    ]);
                    echo '<div class="notice notice-success"><p>Emblema <strong>' . esc_html($name) . '</strong> criado com sucesso.</p></div>';
                }
            } else {
                echo '<div class="notice notice-error"><p>ID e Nome são obrigatórios.</p></div>';
            }
        }

        if ($action === 'delete') {
            $badge_id = sanitize_key($_POST['badge_id'] ?? '');
            if ($badge_id) {
                $wpdb->delete($table, ['badge_id' => $badge_id]);
                echo '<div class="notice notice-success"><p>Emblema <strong>' . esc_html($badge_id) . '</strong> removido.</p></div>';
            }
        }

        if ($action === 'give') {
            $nickname = sanitize_text_field($_POST['nickname'] ?? '');
            $badge_id = sanitize_key($_POST['badge_id'] ?? '');

            if ($nickname && $badge_id) {
                $user = get_user_by('login', $nickname);
                if (!$user) {
                    echo '<div class="notice notice-error"><p>Jogador <strong>' . esc_html($nickname) . '</strong> não encontrado.</p></div>';
                } else {
                    if (wiredclub_player_has_badge($user->ID, $badge_id)) {
                        $badge = $wpdb->get_row($wpdb->prepare("SELECT name FROM $table WHERE badge_id = %s", $badge_id));
                        echo '<div class="notice notice-warning"><p><strong>' . esc_html($nickname) . '</strong> já possui o emblema <strong>' . esc_html($badge->name ?? $badge_id) . '</strong>.</p></div>';
                    } else {
                        wiredclub_give_badge($user->ID, $badge_id);
                        $badge = $wpdb->get_row($wpdb->prepare("SELECT name FROM $table WHERE badge_id = %s", $badge_id));
                        echo '<div class="notice notice-success"><p>Emblema <strong>' . esc_html($badge->name ?? $badge_id) . '</strong> dado a <strong>' . esc_html($nickname) . '</strong>.</p></div>';
                    }
                }
            }
        }

        if ($action === 'revoke') {
            $nickname = sanitize_text_field($_POST['nickname'] ?? '');
            $badge_id = sanitize_key($_POST['badge_id'] ?? '');

            if ($nickname && $badge_id) {
                $user = get_user_by('login', $nickname);
                if (!$user) {
                    echo '<div class="notice notice-error"><p>Jogador <strong>' . esc_html($nickname) . '</strong> não encontrado.</p></div>';
                } else {
                    wiredclub_revoke_badge($user->ID, $badge_id);
                    echo '<div class="notice notice-success"><p>Emblema <strong>' . esc_html($badge_id) . '</strong> removido de <strong>' . esc_html($nickname) . '</strong>.</p></div>';
                }
            }
        }

        if ($action === 'give_all') {
            $badge_id = sanitize_key($_POST['badge_id'] ?? '');
            if ($badge_id) {
                $badge = $wpdb->get_row($wpdb->prepare("SELECT name FROM $table WHERE badge_id = %s", $badge_id));
                if (!$badge) {
                    echo '<div class="notice notice-error"><p>Emblema <strong>' . esc_html($badge_id) . '</strong> não encontrado.</p></div>';
                } else {
                    $count = wiredclub_give_badge_to_all($badge_id);
                    echo '<div class="notice notice-success"><p>Emblema <strong>' . esc_html($badge->name) . '</strong> dado a <strong>' . $count . '</strong> jogador(es).</p></div>';
                }
            }
        }

        if ($action === 'revoke_all') {
            $badge_id = sanitize_key($_POST['badge_id'] ?? '');
            if ($badge_id) {
                $badge = $wpdb->get_row($wpdb->prepare("SELECT name FROM $table WHERE badge_id = %s", $badge_id));
                $count = wiredclub_revoke_badge_from_all($badge_id);
                echo '<div class="notice notice-success"><p>Emblema <strong>' . esc_html($badge->name ?? $badge_id) . '</strong> removido de <strong>' . $count . '</strong> jogador(es).</p></div>';
            }
        }
    }

    // Consultar emblemas de jogador (via GET para não conflitar com POST actions)
    $lookup_nickname = sanitize_text_field($_GET['lookup_nickname'] ?? '');
    $lookup_badges = null;
    if (!empty($lookup_nickname)) {
        $lookup_user = get_user_by('login', $lookup_nickname);
        if ($lookup_user) {
            $lookup_badges = wiredclub_get_player_badges($lookup_user->ID);
        }
    }

    // Buscar emblemas
    $badges = $wpdb->get_results("SELECT * FROM $table ORDER BY created_at DESC");
    ?>
        <style>
        #wc-badges-grid .form-table th { width: 110px; padding-left: 0; }
        #wc-badges-grid .form-table td { padding-right: 0; }
        #wc-badges-grid .form-table .regular-text { width: 100%; box-sizing: border-box; }
        #wc-badges-grid .form-table select { width: 100%; max-width: 100%; box-sizing: border-box; }
        #wc-badges-grid .wc-nickname-wrap { width: 100%; }
        </style>

        <div id="wc-badges-grid" style="display:flex;flex-wrap:wrap;gap:20px;margin-top:20px;">

        <!-- Criar Emblema -->
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;flex:1 1 400px;min-width:300px;box-sizing:border-box;">
            <h2 style="margin-top:0;">Criar Emblema</h2>
            <form method="post">
                <?php wp_nonce_field('wiredclub_badges_action'); ?>
                <input type="hidden" name="wc_action" value="create" />
                <table class="form-table">
                    <tr>
                        <th><label for="badge_id">ID do Emblema</label></th>
                        <td>
                            <input type="text" id="badge_id" name="badge_id" class="regular-text" required placeholder="ex: emb_wiredclub" />
                            <p class="description">Identificador único (sem espaços, minúsculo)</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="badge_name">Nome</label></th>
                        <td><input type="text" id="badge_name" name="badge_name" class="regular-text" required placeholder="ex: Membro Wired Club" /></td>
                    </tr>
                    <tr>
                        <th><label>Imagem</label></th>
                        <td>
                            <input type="hidden" id="attachment_id" name="attachment_id" value="0" />
                            <div id="badge-image-preview" style="margin-bottom:10px;"></div>
                            <button type="button" class="button" id="upload-badge-image">Selecionar Imagem</button>
                            <button type="button" class="button" id="remove-badge-image" style="display:none;">Remover</button>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Criar Emblema', 'primary'); ?>
            </form>
        </div>

        <!-- Dar Emblema a Jogador -->
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;flex:1 1 400px;min-width:300px;box-sizing:border-box;">
            <h2 style="margin-top:0;">Dar Emblema a Jogador</h2>
            <form method="post">
                <?php wp_nonce_field('wiredclub_badges_action'); ?>
                <input type="hidden" name="wc_action" value="give" />
                <table class="form-table">
                    <tr>
                        <th><label for="give_nickname">Nickname</label></th>
                        <td>
                            <div class="wc-nickname-wrap">
                                <input type="text" id="give_nickname" name="nickname" class="regular-text wc-nickname-input" required autocomplete="off" />
                                <span class="wc-nick-loading">buscando...</span>
                                <div class="wc-nickname-results"></div>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="give_badge">Emblema</label></th>
                        <td>
                            <select name="badge_id" id="give_badge" required>
                                <option value="">Selecione...</option>
                                <?php foreach ($badges as $badge) : ?>
                                    <option value="<?php echo esc_attr($badge->badge_id); ?>">
                                        <?php echo esc_html($badge->name); ?> (<?php echo esc_html($badge->badge_id); ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Dar Emblema', 'primary'); ?>
            </form>
        </div>

        <!-- Revogar Emblema -->
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;flex:1 1 400px;min-width:300px;box-sizing:border-box;">
            <h2 style="margin-top:0;">Revogar Emblema de Jogador</h2>
            <form method="post">
                <?php wp_nonce_field('wiredclub_badges_action'); ?>
                <input type="hidden" name="wc_action" value="revoke" />
                <table class="form-table">
                    <tr>
                        <th><label for="revoke_nickname">Nickname</label></th>
                        <td>
                            <div class="wc-nickname-wrap">
                                <input type="text" id="revoke_nickname" name="nickname" class="regular-text wc-nickname-input" required autocomplete="off" />
                                <span class="wc-nick-loading">buscando...</span>
                                <div class="wc-nickname-results"></div>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="revoke_badge">Emblema</label></th>
                        <td>
                            <select name="badge_id" id="revoke_badge" required>
                                <option value="">Selecione...</option>
                                <?php foreach ($badges as $badge) : ?>
                                    <option value="<?php echo esc_attr($badge->badge_id); ?>">
                                        <?php echo esc_html($badge->name); ?> (<?php echo esc_html($badge->badge_id); ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Revogar Emblema', 'delete'); ?>
            </form>
        </div>

        <!-- Dar Emblema a Todos os Jogadores -->
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;flex:1 1 400px;min-width:300px;box-sizing:border-box;">
            <h2 style="margin-top:0;">Dar Emblema a Todos os Jogadores</h2>
            <form method="post">
                <?php wp_nonce_field('wiredclub_badges_action'); ?>
                <input type="hidden" name="wc_action" value="give_all" />
                <table class="form-table">
                    <tr>
                        <th><label for="give_all_badge">Emblema</label></th>
                        <td>
                            <select name="badge_id" id="give_all_badge" required>
                                <option value="">Selecione...</option>
                                <?php foreach ($badges as $badge) : ?>
                                    <option value="<?php echo esc_attr($badge->badge_id); ?>">
                                        <?php echo esc_html($badge->name); ?> (<?php echo esc_html($badge->badge_id); ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Dar a Todos', 'primary'); ?>
            </form>
        </div>

        <!-- Revogar Emblema de Todos os Jogadores -->
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;flex:1 1 400px;min-width:300px;box-sizing:border-box;">
            <h2 style="margin-top:0;">Revogar Emblema de Todos os Jogadores</h2>
            <form method="post">
                <?php wp_nonce_field('wiredclub_badges_action'); ?>
                <input type="hidden" name="wc_action" value="revoke_all" />
                <table class="form-table">
                    <tr>
                        <th><label for="revoke_all_badge">Emblema</label></th>
                        <td>
                            <select name="badge_id" id="revoke_all_badge" required>
                                <option value="">Selecione...</option>
                                <?php foreach ($badges as $badge) : ?>
                                    <option value="<?php echo esc_attr($badge->badge_id); ?>">
                                        <?php echo esc_html($badge->name); ?> (<?php echo esc_html($badge->badge_id); ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Revogar de Todos', 'delete'); ?>
            </form>
        </div>

        <!-- Consultar Emblemas de Jogador -->
        <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;flex:1 1 400px;min-width:300px;box-sizing:border-box;">
            <h2 style="margin-top:0;">Consultar Emblemas de Jogador</h2>
            <form method="get">
                <input type="hidden" name="page" value="wiredclub-addons" />
                <input type="hidden" name="tab" value="badges" />
                <table class="form-table">
                    <tr>
                        <th><label for="lookup_nickname">Nickname</label></th>
                        <td>
                            <div class="wc-nickname-wrap">
                                <input type="text" id="lookup_nickname" name="lookup_nickname" class="regular-text wc-nickname-input" required autocomplete="off" value="<?php echo esc_attr($lookup_nickname); ?>" />
                                <span class="wc-nick-loading">buscando...</span>
                                <div class="wc-nickname-results"></div>
                            </div>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Consultar', 'secondary'); ?>
            </form>

            <?php if (!empty($lookup_nickname)) : ?>
                <?php if ($lookup_badges === null) : ?>
                    <div class="notice notice-error inline"><p>Jogador <strong><?php echo esc_html($lookup_nickname); ?></strong> não encontrado.</p></div>
                <?php elseif (empty($lookup_badges)) : ?>
                    <div class="notice notice-warning inline"><p><strong><?php echo esc_html($lookup_nickname); ?></strong> não possui nenhum emblema.</p></div>
                <?php else : ?>
                    <h3>Emblemas de <?php echo esc_html($lookup_nickname); ?> (<?php echo count($lookup_badges); ?>)</h3>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th style="width:60px;">Imagem</th>
                                <th>ID</th>
                                <th>Nome</th>
                                <th style="width:100px;">Destaque</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($lookup_badges as $lb) :
                                $lb_img = $lb['attachment_id'] ? wp_get_attachment_url((int) $lb['attachment_id']) : '';
                            ?>
                                <tr>
                                    <td>
                                        <?php if ($lb_img) : ?>
                                            <img src="<?php echo esc_url($lb_img); ?>" alt="" style="max-width:40px;max-height:40px;" />
                                        <?php else : ?>
                                            <span style="color:#999;">—</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><code><?php echo esc_html($lb['badge_id']); ?></code></td>
                                    <td><?php echo esc_html($lb['name']); ?></td>
                                    <td>
                                        <?php if (!empty($lb['is_featured'])) : ?>
                                            <span style="color:#0073aa;font-weight:bold;">&#9733; Sim</span>
                                        <?php else : ?>
                                            <span style="color:#999;">—</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        </div><!-- /flex-wrap -->

        <!-- Lista de Emblemas -->
        <h2 style="margin-top:30px;">Emblemas Cadastrados (<?php echo count($badges); ?>)</h2>
        <?php if (empty($badges)) : ?>
            <p>Nenhum emblema cadastrado.</p>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width:80px;">Imagem</th>
                        <th>ID</th>
                        <th>Nome</th>
                        <th>Attachment ID</th>
                        <th>Criado em</th>
                        <th style="width:100px;">Ação</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($badges as $badge) :
                        $img_url = $badge->attachment_id ? wp_get_attachment_url($badge->attachment_id) : '';
                    ?>
                        <tr>
                            <td>
                                <?php if ($img_url) : ?>
                                    <img src="<?php echo esc_url($img_url); ?>" alt="" style="max-width:50px;max-height:50px;" />
                                <?php else : ?>
                                    <span style="color:#999;">—</span>
                                <?php endif; ?>
                            </td>
                            <td><code><?php echo esc_html($badge->badge_id); ?></code></td>
                            <td><strong><?php echo esc_html($badge->name); ?></strong></td>
                            <td><?php echo $badge->attachment_id ?: '—'; ?></td>
                            <td><?php echo esc_html(date_i18n('d/m/Y H:i', strtotime($badge->created_at))); ?></td>
                            <td>
                                <form method="post" style="display:inline;">
                                    <?php wp_nonce_field('wiredclub_badges_action'); ?>
                                    <input type="hidden" name="wc_action" value="delete" />
                                    <input type="hidden" name="badge_id" value="<?php echo esc_attr($badge->badge_id); ?>" />
                                    <button type="submit" class="button button-small" onclick="return confirm('Excluir o emblema <?php echo esc_js($badge->name); ?>?')">
                                        Excluir
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

    <script>
    jQuery(document).ready(function($) {
        var frame;
        $('#upload-badge-image').on('click', function(e) {
            e.preventDefault();
            if (frame) { frame.open(); return; }
            frame = wp.media({
                title: 'Selecionar Imagem do Emblema',
                button: { text: 'Usar esta imagem' },
                multiple: false,
                library: { type: 'image' }
            });
            frame.on('select', function() {
                var attachment = frame.state().get('selection').first().toJSON();
                $('#attachment_id').val(attachment.id);
                $('#badge-image-preview').html('<img src="' + attachment.url + '" style="max-width:80px;max-height:80px;border:1px solid #ccc;padding:2px;" />');
                $('#remove-badge-image').show();
            });
            frame.open();
        });
        $('#remove-badge-image').on('click', function(e) {
            e.preventDefault();
            $('#attachment_id').val('0');
            $('#badge-image-preview').html('');
            $(this).hide();
        });
    });
    </script>
    <?php wiredclub_render_nickname_autocomplete_js(); ?>
    <?php
}

// ==============================
// Admin - Nickname Autocomplete JS
// ==============================

function wiredclub_render_nickname_autocomplete_js(): void {
    ?>
    <script>
    jQuery(document).ready(function($) {
        var ajaxUrl = <?php echo wp_json_encode(admin_url('admin-ajax.php')); ?>;
        var debounceTimers = {};

        $('.wc-nickname-input').each(function() {
            var $input = $(this);
            var $wrap = $input.closest('.wc-nickname-wrap');
            var $results = $wrap.find('.wc-nickname-results');
            var $loading = $wrap.find('.wc-nick-loading');
            var inputId = $input.attr('id') || Math.random().toString(36).substr(2);
            var activeIndex = -1;

            function buildAvatarUrl(nick) {
                return 'https://www.habbo.com.br/habbo-imaging/avatarimage?img_format=png&user=' + encodeURIComponent(nick) + '&direction=2&head_direction=2&size=s&headonly=1';
            }

            function showResults(users) {
                $results.empty();
                if (!users.length) { $results.hide(); return; }
                activeIndex = -1;
                users.forEach(function(u, i) {
                    var $item = $('<div class="wc-nick-item" data-index="' + i + '">')
                        .append('<img src="' + buildAvatarUrl(u.value) + '" alt="" />')
                        .append('<span>' + $('<span>').text(u.label).html() + '</span>');
                    $item.on('mousedown', function(e) {
                        e.preventDefault();
                        $input.val(u.value);
                        $results.hide();
                    });
                    $results.append($item);
                });
                $results.show();
            }

            $input.on('input', function() {
                var term = $input.val().trim();
                clearTimeout(debounceTimers[inputId]);

                if (term.length < 2) {
                    $results.hide();
                    $loading.hide();
                    return;
                }

                $loading.show();
                debounceTimers[inputId] = setTimeout(function() {
                    $.ajax({
                        url: ajaxUrl,
                        data: { action: 'wiredclub_search_users', term: term },
                        dataType: 'json',
                        success: function(data) {
                            $loading.hide();
                            showResults(data);
                        },
                        error: function() {
                            $loading.hide();
                            $results.hide();
                        }
                    });
                }, 300);
            });

            $input.on('keydown', function(e) {
                var $items = $results.find('.wc-nick-item');
                if (!$items.length || !$results.is(':visible')) return;

                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    activeIndex = Math.min(activeIndex + 1, $items.length - 1);
                    $items.removeClass('active').eq(activeIndex).addClass('active');
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    activeIndex = Math.max(activeIndex - 1, 0);
                    $items.removeClass('active').eq(activeIndex).addClass('active');
                } else if (e.key === 'Enter' && activeIndex >= 0) {
                    e.preventDefault();
                    $items.eq(activeIndex).trigger('mousedown');
                } else if (e.key === 'Escape') {
                    $results.hide();
                }
            });

            $input.on('blur', function() {
                setTimeout(function() { $results.hide(); }, 200);
            });

            $input.on('focus', function() {
                if ($results.find('.wc-nick-item').length && $input.val().trim().length >= 2) {
                    $results.show();
                }
            });
        });
    });
    </script>
    <?php
}

// ==============================
// Painel Admin - Webhooks
// ==============================

function wiredclub_maybe_create_webhooks_table(): void {
    global $wpdb;
    $charset = $wpdb->get_charset_collate();
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $table = $wpdb->prefix . 'wiredclub_webhooks';
    dbDelta("CREATE TABLE IF NOT EXISTS $table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        category_id BIGINT UNSIGNED NOT NULL,
        webhook_url VARCHAR(500) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY category_id (category_id)
    ) $charset;");
}

function wiredclub_webhooks_content(): void {
    global $wpdb;
    wiredclub_maybe_create_webhooks_table();
    $table = $wpdb->prefix . 'wiredclub_webhooks';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && current_user_can('manage_options')) {
        if (!wp_verify_nonce($_POST['_wpnonce'] ?? '', 'wiredclub_webhooks_action')) {
            wp_die('Ação não autorizada.');
        }

        $action = sanitize_text_field($_POST['wc_action'] ?? '');

        if ($action === 'save') {
            $category_id = absint($_POST['category_id'] ?? 0);
            $webhook_url = esc_url_raw(trim($_POST['webhook_url'] ?? ''));

            if ($category_id && $webhook_url) {
                $wpdb->replace($table, [
                    'category_id' => $category_id,
                    'webhook_url' => $webhook_url,
                    'created_at'  => current_time('mysql'),
                ]);
                echo '<div class="notice notice-success"><p>Webhook salvo com sucesso.</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>Categoria e URL do webhook são obrigatórios.</p></div>';
            }
        }

        if ($action === 'delete') {
            $id = absint($_POST['webhook_id'] ?? 0);
            if ($id) {
                $wpdb->delete($table, ['id' => $id]);
                echo '<div class="notice notice-success"><p>Webhook removido.</p></div>';
            }
        }

        if ($action === 'test') {
            $webhook_url = esc_url_raw(trim($_POST['webhook_url'] ?? ''));
            if ($webhook_url) {
                $payload = [
                    'content' => '',
                    'embeds'  => [[
                        'title'       => '✅ Teste de Webhook',
                        'description' => 'Este é um envio de teste do WiredClub Addons.',
                        'color'       => 3066993,
                        'footer'      => ['text' => 'Enviado em ' . date_i18n('d/m/Y H:i')],
                    ]],
                ];
                $response = wp_remote_post($webhook_url, [
                    'headers'     => ['Content-Type' => 'application/json'],
                    'body'        => wp_json_encode($payload),
                    'timeout'     => 15,
                    'data_format' => 'body',
                ]);
                if (is_wp_error($response)) {
                    echo '<div class="notice notice-error"><p>Erro ao enviar: <strong>' . esc_html($response->get_error_message()) . '</strong></p></div>';
                } else {
                    $code = wp_remote_retrieve_response_code($response);
                    if ($code >= 200 && $code < 300) {
                        echo '<div class="notice notice-success"><p>Teste enviado com sucesso! (HTTP ' . $code . ')</p></div>';
                    } else {
                        $body = wp_remote_retrieve_body($response);
                        echo '<div class="notice notice-error"><p>Discord retornou HTTP <strong>' . $code . '</strong>: ' . esc_html($body) . '</p></div>';
                    }
                }
            }
        }
    }

    $webhooks       = $wpdb->get_results("SELECT * FROM $table ORDER BY created_at DESC");
    $categories     = get_categories(['hide_empty' => false]);
    $registered_cats = array_column(
        $wpdb->get_results("SELECT category_id FROM $table") ?: [],
        'category_id'
    );
    ?>
    <div style="background:#fff;padding:20px;border:1px solid #ccd0d4;margin-top:20px;max-width:600px;">
        <h2 style="margin-top:0;">Adicionar / Atualizar Webhook</h2>
        <form method="post">
            <?php wp_nonce_field('wiredclub_webhooks_action'); ?>
            <input type="hidden" name="wc_action" value="save" />
            <table class="form-table">
                <tr>
                    <th><label for="wh_category">Categoria</label></th>
                    <td>
                        <select name="category_id" id="wh_category" required>
                            <option value="">Selecione...</option>
                            <?php foreach ($categories as $cat) : ?>
                                <option value="<?php echo esc_attr($cat->term_id); ?>">
                                    <?php echo esc_html($cat->name);
                                    if (in_array((string) $cat->term_id, $registered_cats)) echo ' ✓'; ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="description">✓ = já possui webhook (será sobrescrito ao salvar).</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="wh_url">URL do Webhook</label></th>
                    <td>
                        <input type="url" id="wh_url" name="webhook_url" class="regular-text" required
                               placeholder="https://discord.com/api/webhooks/..." />
                    </td>
                </tr>
            </table>
            <?php submit_button('Salvar Webhook', 'primary'); ?>
        </form>
    </div>

    <h2 style="margin-top:30px;">Webhooks Cadastrados (<?php echo count($webhooks); ?>)</h2>
    <?php if (empty($webhooks)) : ?>
        <p>Nenhum webhook cadastrado.</p>
    <?php else : ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>Categoria</th>
                    <th>URL do Webhook</th>
                    <th>Cadastrado em</th>
                    <th style="width:160px;">Ações</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($webhooks as $wh) :
                    $cat      = get_term($wh->category_id, 'category');
                    $cat_name = ($cat && !is_wp_error($cat)) ? $cat->name : '(categoria removida)';
                ?>
                    <tr>
                        <td><strong><?php echo esc_html($cat_name); ?></strong></td>
                        <td style="word-break:break-all;"><code><?php echo esc_html($wh->webhook_url); ?></code></td>
                        <td><?php echo esc_html(date_i18n('d/m/Y H:i', strtotime($wh->created_at))); ?></td>
                        <td style="display:flex;gap:6px;flex-wrap:wrap;">
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('wiredclub_webhooks_action'); ?>
                                <input type="hidden" name="wc_action" value="test" />
                                <input type="hidden" name="webhook_url" value="<?php echo esc_attr($wh->webhook_url); ?>" />
                                <button type="submit" class="button button-small button-primary">Testar</button>
                            </form>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('wiredclub_webhooks_action'); ?>
                                <input type="hidden" name="wc_action" value="delete" />
                                <input type="hidden" name="webhook_id" value="<?php echo esc_attr($wh->id); ?>" />
                                <button type="submit" class="button button-small"
                                        onclick="return confirm('Remover webhook de <?php echo esc_js($cat_name); ?>?')">
                                    Remover
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <?php
}

// ==============================
// Discord Webhook - Envio
// ==============================

// Gutenberg publica via REST API em 2 etapas:
// 1) transition_post_status dispara (mas categorias ainda NÃO estão salvas)
// 2) handle_terms() salva as categorias
// 3) rest_after_insert_post dispara (categorias já salvas)
//
// Solução: no transition_post_status marcamos um transient;
// o rest_after_insert_post verifica o transient e envia o webhook.
// Para o editor clássico (não-REST), enviamos direto no transition_post_status.

add_action('transition_post_status', function (string $new_status, string $old_status, WP_Post $post): void {
    if ($new_status !== 'publish' || $old_status === 'publish') return;
    if ($post->post_type !== 'post') return;

    if (defined('REST_REQUEST') && REST_REQUEST) {
        // REST (Gutenberg): marcar para envio após categorias serem salvas
        set_transient('wc_webhook_pending_' . $post->ID, 1, 60);
    } else {
        // Editor clássico: categorias já estão disponíveis
        wiredclub_send_discord_webhook($post);
    }
}, 10, 3);

// Dispara após REST API finalizar, inclusive após handle_terms() salvar categorias
add_action('rest_after_insert_post', function (WP_Post $post): void {
    $key = 'wc_webhook_pending_' . $post->ID;
    if (!get_transient($key)) return;
    delete_transient($key);
    wiredclub_send_discord_webhook($post);
}, 10, 1);

function wiredclub_send_discord_webhook(WP_Post $post): void {
    global $wpdb;
    $table = $wpdb->prefix . 'wiredclub_webhooks';

    $category_ids = wp_get_post_categories($post->ID);
    if (empty($category_ids)) return;

    // Usar absint para segurança e evitar problemas com prepare + spread
    $ids_sql  = implode(',', array_map('absint', $category_ids));
    $webhooks = $wpdb->get_results("SELECT * FROM $table WHERE category_id IN ($ids_sql)");
    if (empty($webhooks)) return;

    $title       = wp_strip_all_tags(get_the_title($post->ID));
    $post_cat     = get_the_category($post->ID);
    $cat_slug     = (!empty($post_cat) && !is_wp_error($post_cat)) ? $post_cat[0]->slug : '';
    $cat_slug_map = [
        'competicoes'          => 'competicoes',
        'desenvolvedor_wired'  => 'desenvolvedores',
        'noticias'             => 'post',
        'show-off'             => 'post',
        'tutoriais'            => 'tutoriais',
    ];
    $url_segment  = isset($cat_slug_map[$cat_slug]) ? $cat_slug_map[$cat_slug] : $cat_slug;
    $post_url     = 'https://wiredclub.com.br/' . ($url_segment ? $url_segment . '/' : '') . $post->post_name;
    $author_name = get_the_author_meta('display_name', $post->post_author);
    // get_the_date() falha fora do loop — usar post_date diretamente
    $date        = date_i18n('d/m/Y', strtotime($post->post_date));
    $thumbnail   = get_the_post_thumbnail_url($post->ID, 'full');

    // get_the_excerpt() fora do loop aplica filtros problemáticos — usar campo direto
    if (!empty(trim($post->post_excerpt))) {
        $excerpt = wp_strip_all_tags($post->post_excerpt);
    } else {
        $excerpt = wp_trim_words(wp_strip_all_tags($post->post_content), 50, '...');
    }
    if (mb_strlen($excerpt) > 300) {
        $excerpt = mb_substr($excerpt, 0, 297) . '...';
    }

    foreach ($webhooks as $wh) {
        $cat      = get_term((int) $wh->category_id, 'category');
        $cat_name = ($cat && !is_wp_error($cat)) ? $cat->name : '';

        $embed = [
            'title'       => '### ' . ($title ?: 'Novo post'),
            'url'         => $post_url,
            'description' => '-# Por ' . $author_name . ' - ' . $date,
            'color'       => 16747008,
            'fields'      => [[
                'name'   => ' ',
                'value'  => $excerpt ?: '—',
                'inline' => false,
            ]],
            'footer' => [
                'text' => $cat_name . " - wiredclub.com.br",
            ],
        ];

        if ($thumbnail) {
            $embed['image'] = ['url' => $thumbnail];
        }

        $payload = [
            'content' => '@everyone',
            'tts'     => false,
            'embeds'  => [$embed],
        ];

        $response = wp_remote_post($wh->webhook_url, [
            'headers'     => ['Content-Type' => 'application/json'],
            'body'        => wp_json_encode($payload),
            'timeout'     => 15,
            'data_format' => 'body',
        ]);

        if (is_wp_error($response)) {
            error_log('[WiredClub] Webhook error for post ' . $post->ID . ': ' . $response->get_error_message());
        } elseif (wp_remote_retrieve_response_code($response) >= 400) {
            error_log('[WiredClub] Webhook HTTP ' . wp_remote_retrieve_response_code($response) . ' for post ' . $post->ID . ': ' . wp_remote_retrieve_body($response));
        }
    }
}

<?php require_once('./app/autoload.php'); ?>
<!DOCTYPE html>
<html lang="<?= Init::$app_lang; ?>">
<head>
     <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <meta http-equiv="X-UA-Compatible" content="ie=edge">
     <title><?= Init::$app_name; ?></title>
     <link rel="stylesheet" href="assets/css/main.css">
</head>
<body>
     <h1>Blog</h1>
     <hr>
     <?php
     $pages = new Paginator('2','page');
     $stmt = $db->query('SELECT * FROM blog_posts ORDER BY post_id');

     $pages->set_total($stmt->rowCount());

     $posts = $db->query('SELECT * FROM blog_posts ORDER BY post_id DESC ' . $pages->get_limit());

     foreach ($posts as $post) { ?>

     <div>
          <h3><?= $post['post_title']; ?></h3>
          <p><?= $post['post_body']; ?></p>
          <a href=""></a>
          <hr>
     </div>

     <?php } ?>

     <?php echo $pages->page_links(); ?>
</body>
</html>

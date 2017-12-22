<?php
class Auth {
     public static $error = "";

     public function logout() {
          DB::query('DELETE FROM login WHERE login_userid=:userid', array(':userid'=>self::loggedin()));
          setcookie("" . DB::$system_cookie_name . "", '1', time()-3600);
          setcookie("" . DB::$system_cookie_name . "_", '1', time()-3600);
          header('Location: index.php');
          exit();
     }
     public static function loggedin() {
          if (isset($_COOKIE['' . DB::$system_cookie_name . ''])) {
               if (DB::query('SELECT login_userid FROM login WHERE login_token=:token', [':token'=>sha1($_COOKIE['' . DB::$system_cookie_name . ''])])) {
                    $userid = DB::query('SELECT login_userid FROM login WHERE login_token=:token', [':token'=>sha1($_COOKIE['' . DB::$system_cookie_name . ''])])[0]['login_userid'];
                    if (isset($_COOKIE['' . DB::$system_cookie_name . '_'])) {
                         return $userid;
                    } else {
                         $cstrong = True;
                         $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                         DB::query('INSERT INTO login VALUES (\'\', :token, :user_id)', [':token'=>sha1($token), ':user_id'=>$userid]);
                         DB::query('DELETE FROM login WHERE login_token=:token', [':token'=>sha1($_COOKIE["" . DB::$system_cookie_name . ""])]);
                         setcookie("" . DB::$system_cookie_name . "", $token, time() + 60 * 60 * 24 * 30, '/', NULL, NULL, TRUE);
                         setcookie("" . DB::$system_cookie_name . "_", '1', time() + 60 * 60 * 24 * 3, '/', NULL, NULL, TRUE);
                         return $userid;
                    }
               }
          }
          return false;
     }
     public function guard() {
          if (!self::loggedin()) {
               require_once("../app/modules/guard-error.html");
               exit();
          }
     }
     # login
     public function login($login, $pass) {
          if (strpos($login, '@') !== false) {
               if (DB::query('SELECT user_email FROM users WHERE user_email=:email', [':email'=>$login])) {
                    if (password_verify($pass, DB::query('SELECT user_password FROM users WHERE user_email=:email', [':email'=>$login])[0]['user_password'])) {
                         $cstrong = True;
                         $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                         $user_id = DB::query('SELECT user_id FROM users WHERE user_email=:email', [':email'=>$login])[0]['user_id'];
                         DB::query('INSERT INTO login VALUES (\'\', :token, :user_id)', [':token'=>sha1($token), ':user_id'=>$user_id]);
                         setcookie("" . DB::$system_cookie_name . "", $token, time() + 60 * 60 * 24 * 30, '/', NULL, NULL, TRUE);
                         setcookie("" . DB::$system_cookie_name . "_", '1', time() + 60 * 60 * 24 * 3, '/', NULL, NULL, TRUE);
                         header("Location: index.php");
                         exit();
                    }else {self::$error = "Niepoprawne hasło!";}
               }else {self::$error = "Użytkownik niezarejestrowany!";}
          }else {
               if (DB::query('SELECT user_name FROM users WHERE user_name=:username', [':username'=>$login])) {
                    if (password_verify($pass, DB::query('SELECT user_password FROM users WHERE user_name=:username', [':username'=>$login])[0]['user_password'])) {
                         $cstrong = True;
                         $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                         $user_id = DB::query('SELECT user_id FROM users WHERE user_name=:username', [':username'=>$login])[0]['user_id'];
                         DB::query('INSERT INTO login VALUES (\'\', :token, :user_id)', [':token'=>sha1($token), ':user_id'=>$user_id]);
                         setcookie("" . DB::$system_cookie_name . "", $token, time() + 60 * 60 * 24 * 30, '/', NULL, NULL, TRUE);
                         setcookie("" . DB::$system_cookie_name . "_", '1', time() + 60 * 60 * 24 * 3, '/', NULL, NULL, TRUE);
                         header("Location: index.php");
                         exit();
                    }else {self::$error = "Niepoprawne hasło!";}
               }else {self::$error = "Użytkownik niezarejestrowany!";}
          }
     }
     # register
     public function register($name, $email, $password) {
          if (!empty($name) && !empty($email) && !empty($password)) {
          if (strlen($name) >= 2 && strlen($name) <= 16) {
               if (strlen($email) >= 6 && strlen($email) <= 128) {
               if (preg_match('/[a-zA-Z]+/', $name)) {
                    if (strpos($email, '@') !== false) {
                    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                         if (!DB::query('SELECT user_email FROM users WHERE user_email=:email', [':email'=>$email])) {
                         if (strlen($password) >= 8 && strlen($password) <= 64) {

                              DB::query('INSERT INTO users VALUES (\'\', :name, :email, :password)',
                              [':name'=>$name, ':email'=>$email, ':password'=>password_hash($password, PASSWORD_BCRYPT);]);

                              self::login($email, $password);

                         }else {self::$error = "Niepoprawna długość hasła (min: 8, max: 64)";}
                         }else {self::$error = "Adres jest niepoprawny!";}
                    }else {self::$error = "Podany adres email jest już zajęty!";}
                    }else {self::$error = "Adres email musi zawierać znak @ (małpy)!";}
               }else {self::$error = "Niepoprawna długość imienia (min: 3, max: 16)";}
               }else {self::$error = "Niepoprawna długość nazwiska (min: 2, max: 16)";}
          }else {self::$error = "Niepoprawna długość imienia (min: 2, max: 16)";}
          }else {self::$error = "Jedno lub kilka pól są puste!";}
     }

     // # forgot password
     // public function forgotPassword($email) {
     //      if (strpos($email, '@') !== false) {
     //      if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
     //           $cstrong = True;
     //           $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
     //           $email = $_POST['email'];
     //           $user_id = DB::query('SELECT user_id FROM users WHERE user_email=:email', [':email'=>$email])[0]['user_id'];
     //           DB::query('INSERT INTO password_tokens VALUES (\'\', :token, :user_id)', [':token'=>sha1($token), ':user_id'=>$user_id]);
     //           Mail::sendMail('Zresetuj hasło.', "<a href='http://localhost/social-network/change-password.php?token=$token'>http://localhost/social-network/change-password.php?token=$token</a>", $email);
     //           self::$error = 'Sprawdź swoją pocztę.';
     //      }else {self::$error = "Adres jest niepoprawny!";}
     //      }else {self::$error = "Adres email musi zawierać znak @ (małpy)!";}
     // }
     // # change password
     // public function changePassword($opass, $npass, $rnpass) {
     //      if (password_verify($opass, DB::query('SELECT user_password FROM users WHERE user_id=:userid', [':userid'=>self::loggedin()])[0]['user_password'])) {
     //           if ($npass == $rnpass) {
     //                if (strlen($npass) >= 8 && strlen($npass) <= 64) {
     //                     DB::query('UPDATE users SET user_password=:newpassword WHERE user_id=:userid', array(':newpassword'=>password_hash($npass, PASSWORD_BCRYPT), ':userid'=>self::loggedin()));
     //                     self::logout();
     //                     echo 'Password changed successfully!';
     //                }
     //           }else {self::$error = "Podane hasła nie są identyczne!";}
     //      }else {self::$error = "Niepoprawne stare hasło!";}
     // }
     // # change password token
     // public function changePasswordToken($npass, $rnpass) {
     //      if ($npass == $rnpass) {
     //           if (strlen($npass) >= 6 && strlen($npass) <= 60) {
     //                DB::query('UPDATE users SET user_password=:newpassword WHERE user_id=:userid', array(':newpassword'=>password_hash($npass, PASSWORD_BCRYPT), ':userid'=>self::loggedin()));
     //                echo 'Password changed successfully!';
     //                DB::query('DELETE FROM password_tokens WHERE password_tokens_userid=:userid', array(':userid'=>self::loggedin()));
     //           }
     //      }else {self::$error = "Podane hasła nie są identyczne!";}
     // }
}
?>

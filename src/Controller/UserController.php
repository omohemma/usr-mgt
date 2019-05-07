<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Swagger\Annotations as SWG;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class UserController extends AbstractController
{
    /**
     * @Route("/user", name="user")
     */
    // public function index()
    // {
    //     return $this->json([
    //         'message' => 'Welcome to your new controller!',
    //         'path' => 'src/Controller/UserController.php',
    //     ]);
    // }

    /**
     * @Route("/register", name="api_register",methods={"POST"}),
     *
     * @SWG\Parameter(
     *     name="email",
     *     in="formData",
     *     type="string",
     *     description="The field of user email"
     * ),
     *  @SWG\Parameter(
     *     name="password",
     *     in="formData",
     *     type="string",
     *     description="The field of user's password"
     * ),
     *  @SWG\Parameter(
     *     name="password_confirmation",
     *     in="formData",
     *     type="string",
     *     description="The field to confirm user's password"
     * ),
     * @SWG\Parameter(
     *     name="roles",
     *     in="formData",
     *     type="string",
     *     description="The field user's roles"
     * ),
     * @SWG\Response(
     *     response=200,
     *     description="Success",
     * )
     */

    public function register(ObjectManager $om, UserPasswordEncoderInterface $passwordEncoder, Request $request)
    {

        $user = new User();
        $email = $request->request->get("email");
        $password = $request->request->get("password");
        $passwordConfirmation = $request->request->get("password_confirmation");
        $roles = $request->request->get("roles");
        $errors = [];
        if ($password != $passwordConfirmation) {
            $errors[] = "Password does not match the password confirmation.";
        }
        if (strlen($password) < 6) {
            $errors[] = "Password should be at least 6 characters.";
        }
        if (!$errors) {
            $encodedPassword = $passwordEncoder->encodePassword($user, $password);
            $user->setEmail($email);

            $roles = explode(',', $roles);
            foreach ($roles as &$role) {
                $role = strtoupper('role_' . $role);
            }

            $user->setRoles($roles);
            $user->setPassword($encodedPassword);
            try
            {
                $om->persist($user);
                $om->flush();

                // TODO: Do redirection...

                return $this->json([
                    'error' => null,
                    'success' => true,
                ]);

            } catch (UniqueConstraintViolationException $e) {
                $errors[] = "The email provided already has an account!";
            } catch (\Exception $e) {
                $errors[] = "Unable to save new user at this time.";
            }
        }

        return $this->json([
            'errors' => $errors,
        ], 400);
    }
}

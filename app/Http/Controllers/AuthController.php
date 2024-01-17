<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'status' => false,
                    'errors' => $validator->errors()
                ], 401);
            }

            if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {

                $userToken = Auth::user()->createToken('auth-user')->plainTextToken;
                return response()->json([
                    'status' => true,
                    'message' => 'User authenticated successfully',
                    'token' => $userToken,
                    'user' => auth()->user()
                ], 200);
            }

            return response()->json(['status' => false, 'message' => 'Incorrect email or password. Try again.'], 401);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:3|confirmed',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'status' => false,
                    'errors' => $validator->errors()
                ], 401);
            }

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            $userToken = $user->createToken('auth-user')->plainTextToken;
            return response()->json([
                'status' => true,
                'message' => 'User created successfull',
                'token' => $userToken,
                'user' => $user
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function update(Request $request)
    {

        $user = $request->user();

        $user['name'] = $request->name;

        if (isset($request->password)) {
            if ($request->password_confirmation == $request->password) {
                $user['password'] = Hash::make($request->password);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => 'The password does not match'
                ], 200);
            }
        }

        if ($request->avatar) {

            $userAvatar = array_slice(explode('/', rtrim($user['avatar'], '/')), -1)[0];

            if (Storage::exists('public/uploads/avatars/' . $userAvatar)) {
                Storage::delete('public/uploads/avatars/' . $userAvatar);
            }

            $path = $request->file('avatar')->storeAs(
                'uploads/avatars',
                time() . '.' . $request->file('avatar')->extension(),
                'public'
            );

            $user['avatar'] = asset(Storage::url($path));
        }

        $user->update();

        return response()->json([
            'status' => true,
            'message' => 'User updated successfully'
        ], 200);
    }

    public function checkToken(Request $request)
    {
        return response()->json([
            'status' => true,
            'user' => $request->user()
        ], 200);
    }

    public function logout()
    {
        auth()->user()->currentAccessToken()->delete();

        return response()->json([
            'status' => true,
            'message' => 'User disconnected successfully'
        ], 200);
    }
}

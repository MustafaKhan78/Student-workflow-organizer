import mongoose from 'mongoose';
import { promisify } from 'util';
import AppError from '@utils/app_error';
import Role from '@utils/authorization/roles/role';
import { REQUIRE_ACTIVATION } from '@config/app_config';
import {
    getGithubOAuthUser,
    getGithubOAuthToken,
    getGithubOAuthUserPrimaryEmail,
} from '@utils/authorization/github';
import AuthUtils from '@utils/authorization/auth_utils';
import searchCookies from '@utils/searchCookie';
import User from '@models/user/user_model';
import {
    Request,
    Res,
    TsoaResponse,
    Controller,
    Get,
    Post,
    Tags,
    Query,
    Body,
    Route,
} from 'tsoa';
import { IReq } from '@root/interfaces/vendors';
import { Response, SuccessResponse } from '@tsoa/runtime';

const generateActivationKey = async () => {
    const randomBytesPromiseified = promisify(require('crypto').randomBytes);
    const activationKey = (await randomBytesPromiseified(32)).toString('hex');
    return activationKey;
};

@Route('api/auth')
@Tags('Authentication')
export class AuthController extends Controller {
    @Get('github/callback')
    @Response(400, 'Invalid access token or code')
    @Response(500, 'User role does not exist. Please contact the admin.')
    @SuccessResponse(
        204,
        `
        - User logged in successfully
        \n- User created successfully`
    )
    public async githubHandler(
        @Request() _req: Express.Request,
        @Res() res: TsoaResponse<204, { message: string }>,
        @Query() code?: string
    ): Promise<void> {
        try {
            const Roles = await Role.getRoles();
            // check if user role exists
            if (!Roles || !Roles.USER) {
                throw new AppError(
                    500,
                    'User role does not exist. Please contact the admin.'
                );
            }

            if (!code) {
                throw new AppError(400, 'Please provide code');
            }

            const tokenData = await getGithubOAuthToken(code);
            if (!tokenData || !tokenData.access_token) {
                throw new AppError(400, 'Invalid code');
            }

            const { access_token } = tokenData;
            const githubUser = await getGithubOAuthUser(access_token);
            if (!githubUser) {
                throw new AppError(400, 'Invalid access token');
            }

            const primaryEmail =
                await getGithubOAuthUserPrimaryEmail(access_token);
            if (!primaryEmail) {
                throw new AppError(400, 'Unable to fetch email from GitHub');
            }

            // check if user exists
            const exists = await User.findOne({ email: primaryEmail });
            if (exists) {
                const accessToken = AuthUtils.generateAccessToken(
                    exists._id.toString()
                );
                const refreshToken = AuthUtils.generateRefreshToken(
                    exists._id.toString()
                );
                AuthUtils.setAccessTokenCookie(this, accessToken);
                AuthUtils.setRefreshTokenCookie(this, refreshToken);
                return res(204, { message: 'User logged in successfully' });
            }

            // create new user with validation
            const userData = {
                name: githubUser.name || githubUser.login || 'GitHub User',
                email: primaryEmail,
                password: null,
                address: githubUser.location || null,
                roles: [Roles.USER.name],
                authorities: Roles.USER.authorities || [],
                restrictions: Roles.USER.restrictions || [],
                githubOauthAccessToken: access_token,
                active: true,
            };

            // Validate required fields
            if (!userData.name || !userData.email) {
                throw new AppError(400, 'Incomplete user data from GitHub');
            }

            const createdUser = await User.create(userData);

            // set cookies
            const accessToken = AuthUtils.generateAccessToken(
                createdUser._id.toString()
            );
            const refreshToken = AuthUtils.generateRefreshToken(
                createdUser._id.toString()
            );
            AuthUtils.setAccessTokenCookie(this, accessToken);
            AuthUtils.setRefreshTokenCookie(this, refreshToken);

            return res(204, { message: 'User created successfully' });
        } catch (error) {
            if (error instanceof AppError) {
                throw error;
            }
            console.error('GitHub OAuth Error:', error);
            throw new AppError(500, 'Authentication failed. Please try again.');
        }
    }

    @Post('login')
    @Response(
        400,
        `- Please provide email and password
        \n- Invalid email or password
        \n- You haven't set a password yet. Please login with GitHub and set a password from your profile page.`
    )
    @Response(401, 'Invalid email or password')
    @Response(
        403,
        'Your account has been banned. Please contact the admin for more information.'
    )
    @SuccessResponse(200, 'OK')
    public async login(
        @Request() _req: Express.Request,
        @Res() res: TsoaResponse<200, { accessToken: string; user: any }>,
        @Body() body?: { email?: string; password?: string }
    ): Promise<void> {
        try {
            const { email, password } = body || {};

            // 1) check if password and email exist
            if (!password || !email) {
                throw new AppError(400, 'Please provide email and password');
            }

            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                throw new AppError(400, 'Please provide a valid email address');
            }

            // 2) check if user exist and password is correct
            const user = await User.findOne({
                email: email.toLowerCase().trim(),
            }).select('+password');

            if (!user) {
                throw new AppError(400, 'Invalid email or password');
            }

            // Check if account is locked due to too many failed attempts (optional)
            if (user.loginAttempts && user.loginAttempts >= 5) {
                const lockTime = user.lockUntil || 0;
                if (lockTime > Date.now()) {
                    throw new AppError(
                        401,
                        'Account temporarily locked. Please try again later.'
                    );
                }
            }

            // check if password exist and it is a string
            if (!user?.password) {
                throw new AppError(
                    400,
                    "You haven't set a password yet. Please login with GitHub and set a password from your profile page."
                );
            }

            const isPasswordCorrect = await user.correctPassword(
                password,
                user.password
            );
            if (!isPasswordCorrect) {
                // Increment login attempts (optional)
                user.loginAttempts = (user.loginAttempts || 0) + 1;
                if (user.loginAttempts >= 5) {
                    user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
                }
                await user.save({ validateBeforeSave: false });

                throw new AppError(401, 'Invalid email or password');
            }

            // Reset login attempts on successful login
            if (user.loginAttempts || user.lockUntil) {
                user.loginAttempts = 0;
                user.lockUntil = undefined;
                await user.save({ validateBeforeSave: false });
            }

            // Check if the account is banned
            if (user.accessRestricted) {
                throw new AppError(
                    403,
                    'Your account has been banned. Please contact the admin for more information.'
                );
            }

            // Check if account is active (if email verification is required)
            if (!user.active && REQUIRE_ACTIVATION) {
                throw new AppError(
                    403,
                    'Please activate your account before logging in. Check your email for activation link.'
                );
            }

            // 3) All correct, send accessToken & refreshToken to client via cookie
            const accessToken = AuthUtils.generateAccessToken(
                user._id.toString()
            );
            const refreshToken = AuthUtils.generateRefreshToken(
                user._id.toString()
            );
            AuthUtils.setAccessTokenCookie(this, accessToken);
            AuthUtils.setRefreshTokenCookie(this, refreshToken);

            // Remove sensitive data from the output
            const userResponse = user.toObject();
            delete userResponse.password;
            delete userResponse.loginAttempts;
            delete userResponse.lockUntil;
            delete userResponse.activationKey;
            if (userResponse.githubOauthAccessToken) {
                delete userResponse.githubOauthAccessToken;
            }

            return res(200, {
                accessToken,
                user: userResponse,
            });
        } catch (error) {
            if (error instanceof AppError) {
                throw error;
            }
            console.error('Login Error:', error);
            throw new AppError(500, 'Login failed. Please try again.');
        }
    }

    @Post('signup')
    @Response(
        400,
        `- Please provide a password
        \n- Please provide an email
        \n- Please provide a name
        `
    )
    @Response(500, 'User role does not exist. Please contact the admin.')
    @Response(409, 'User with this email already exists')
    @SuccessResponse(201, 'Created')
    public async signup(
        @Request() _req: Express.Request,
        @Res() res: TsoaResponse<201, { accessToken: string; user: any }>,
        @Body() body?: { name?: string; email?: string; password?: string }
    ) {
        try {
            const { name, email, password } = body || {};

            // Validate required fields
            if (!password) {
                throw new AppError(400, 'Please provide a password');
            }
            if (!email) {
                throw new AppError(400, 'Please provide an email');
            }
            if (!name) {
                throw new AppError(400, 'Please provide a name');
            }

            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                throw new AppError(400, 'Please provide a valid email address');
            }

            // Validate password strength
            if (password.length < 8) {
                throw new AppError(
                    400,
                    'Password must be at least 8 characters long'
                );
            }

            const activationKey = await generateActivationKey();
            const Roles = await Role.getRoles();

            // check if user role exists
            if (!Roles || !Roles.USER) {
                throw new AppError(
                    500,
                    'User role does not exist. Please contact the admin.'
                );
            }

            // Check if user already exists
            const existingUser = await User.findOne({
                email: email.toLowerCase().trim(),
            });
            if (existingUser) {
                throw new AppError(409, 'User with this email already exists');
            }

            const userpayload = {
                name: name.trim(),
                email: email.toLowerCase().trim(),
                password: password,
                roles: [Roles.USER.name],
                authorities: Roles.USER.authorities || [],
                active: !REQUIRE_ACTIVATION,
                restrictions: Roles.USER.restrictions || [],
                ...(REQUIRE_ACTIVATION && { activationKey }),
                loginAttempts: 0,
            };

            const user = await User.create(userpayload);

            const accessToken = AuthUtils.generateAccessToken(
                user._id.toString()
            );
            const refreshToken = AuthUtils.generateRefreshToken(
                user._id.toString()
            );
            AuthUtils.setAccessTokenCookie(this, accessToken);
            AuthUtils.setRefreshTokenCookie(this, refreshToken);

            // Remove sensitive data from the output
            const userResponse = user.toObject();
            delete userResponse.password;
            delete userResponse.activationKey;
            delete userResponse.loginAttempts;

            return res(201, {
                accessToken,
                user: userResponse,
            });
        } catch (error) {
            if (error instanceof AppError) {
                throw error;
            }
            if (error.code === 11000) {
                throw new AppError(409, 'User with this email already exists');
            }
            console.error('Signup Error:', error);
            throw new AppError(500, 'Signup failed. Please try again.');
        }
    }

    @Get('refreshToken')
    @Response(400, 'You have to login to continue.')
    @Response(400, 'Invalid refresh token')
    @SuccessResponse(204, 'Token refreshed successfully')
    public async tokenRefres(
        @Request() req: IReq,
        @Res() res: TsoaResponse<204, { message: string }>
    ): Promise<void> {
        try {
            // get the refresh token from httpOnly cookie
            const refreshToken = searchCookies(req, 'refresh_token');
            if (!refreshToken) {
                throw new AppError(400, 'You have to login to continue.');
            }

            const refreshTokenPayload =
                await AuthUtils.verifyRefreshToken(refreshToken);
            if (!refreshTokenPayload || !refreshTokenPayload._id) {
                throw new AppError(400, 'Invalid refresh token');
            }

            const user = await User.findById(refreshTokenPayload._id);
            if (!user) {
                throw new AppError(400, 'Invalid refresh token');
            }

            // Check if account is still active
            if (!user.active) {
                throw new AppError(
                    403,
                    'Account is not active. Please contact support.'
                );
            }

            // Check if account is banned
            if (user.accessRestricted) {
                throw new AppError(403, 'Your account has been banned.');
            }

            const accessToken = AuthUtils.generateAccessToken(
                user._id.toString()
            );
            // set or override accessToken cookie
            AuthUtils.setAccessTokenCookie(this, accessToken);

            return res(204, { message: 'Token refreshed successfully' });
        } catch (error) {
            if (error instanceof AppError) {
                throw error;
            }
            console.error('Token Refresh Error:', error);
            throw new AppError(500, 'Token refresh failed. Please try again.');
        }
    }

    @Get('logout')
    @Response(400, 'Please provide access token')
    @SuccessResponse(204, 'Logged out successfully')
    public logout(
        @Request() req: IReq,
        @Res() res: TsoaResponse<204, { message: string }>
    ): void {
        try {
            const accessToken = searchCookies(req, 'access_token');
            if (!accessToken) {
                throw new AppError(400, 'Please provide access token');
            }

            // Clear both access and refresh tokens
            this.setHeader(
                'Set-Cookie',
                'access_token=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Strict, ' +
                    'refresh_token=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Strict'
            );

            return res(204, { message: 'Logged out successfully' });
        } catch (error) {
            if (error instanceof AppError) {
                throw error;
            }
            console.error('Logout Error:', error);
            throw new AppError(500, 'Logout failed. Please try again.');
        }
    }

    @Get('activate')
    @Response(
        400,
        `- Please provide activation key
        \n- Please provide user id
        \n- Please provide a valid user id`
    )
    @Response(404, 'User does not exist')
    @Response(409, 'User is already active')
    @Response(410, 'Activation link has expired')
    @SuccessResponse(200, 'Account activated successfully')
    public async activateAccount(
        @Request() _req: IReq,
        @Res() res: TsoaResponse<200, { user: any }>,
        @Query() id?: string,
        @Query() activationKey?: string
    ): Promise<void> {
        try {
            if (!activationKey) {
                throw new AppError(400, 'Please provide activation key');
            }
            if (!id) {
                throw new AppError(400, 'Please provide user id');
            }

            // check if a valid id
            if (!mongoose.Types.ObjectId.isValid(id)) {
                throw new AppError(400, 'Please provide a valid user id');
            }

            const user = await User.findOne({
                _id: id,
            }).select('+activationKey +activationKeyExpires');

            if (!user) {
                throw new AppError(404, 'User does not exist');
            }

            if (user.active) {
                throw new AppError(409, 'User is already active');
            }

            // Check if activation key has expired (if you implement expiry)
            if (
                user.activationKeyExpires &&
                user.activationKeyExpires < new Date()
            ) {
                throw new AppError(
                    410,
                    'Activation link has expired. Please request a new one.'
                );
            }

            // verify activation key
            if (!user.activationKey || activationKey !== user.activationKey) {
                throw new AppError(400, 'Invalid activation key');
            }

            // activate user
            user.active = true;
            user.activationKey = undefined;
            user.activationKeyExpires = undefined;
            await user.save();

            // Remove sensitive data from the output
            const userResponse = user.toObject();
            delete userResponse.password;

            return res(200, {
                user: userResponse,
            });
        } catch (error) {
            if (error instanceof AppError) {
                throw error;
            }
            console.error('Account Activation Error:', error);
            throw new AppError(
                500,
                'Account activation failed. Please try again.'
            );
        }
    }
}

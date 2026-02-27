import axios from 'axios';
import AppError from '@utils/app_error';
import { IReq } from '@interfaces/vendors';
import {
    Controller,
    Get,
    Request,
    Res,
    Route,
    Security,
    Tags,
    TsoaResponse,
} from 'tsoa';

interface Repository {
    id: number;
    name: string;
    full_name: string;
    description: string | null;
    isFork: boolean;
    language: string | null;
    license: string | null;
    openedIssuesCount: number;
    repoCreatedAt: string;
    url: string;
}

import { Response, SuccessResponse } from '@tsoa/runtime';

@Security('jwt')
@Route('api/github')
@Tags('GitHub')
export class GitHub extends Controller {
    @Get('recent-repo')
    @Response(401, 'You are not logged in')
    @Response(400, 'No repositories found')
    @Response(
        401,
        'GitHub authentication failed. Please reconnect your GitHub account.'
    )
    @Response(403, 'GitHub API rate limit exceeded. Please try again later.')
    @Response(500, 'Failed to fetch repositories from GitHub')
    @SuccessResponse(200, 'OK')
    public async getRecentRepo(
        @Request() req: IReq,
        @Res() res: TsoaResponse<200, { recentRepository: Repository }>
    ) {
        try {
            // Check if user exists and is authenticated
            if (!req.user) {
                throw new AppError(401, 'You are not logged in');
            }

            const { githubOauthAccessToken } = req.user;

            // Check if user has connected GitHub account
            if (!githubOauthAccessToken) {
                throw new AppError(
                    401,
                    'GitHub account not connected. Please connect your GitHub account first.'
                );
            }

            // Fetch user repositories from GitHub
            let userRepositories;
            try {
                userRepositories = await axios.get(
                    'https://api.github.com/user/repos',
                    {
                        headers: {
                            Authorization: `Bearer ${githubOauthAccessToken}`,
                            Accept: 'application/vnd.github.v3+json',
                        },
                        timeout: 10000, // 10 second timeout
                        params: {
                            sort: 'updated',
                            per_page: 100, // Get up to 100 repos to sort properly
                        },
                    }
                );
            } catch (error) {
                if (axios.isAxiosError(error)) {
                    // Handle GitHub API specific errors
                    if (error.response?.status === 401) {
                        throw new AppError(
                            401,
                            'GitHub authentication failed. Please reconnect your GitHub account.'
                        );
                    }
                    if (error.response?.status === 403) {
                        throw new AppError(
                            403,
                            'GitHub API rate limit exceeded. Please try again later.'
                        );
                    }
                    if (error.response?.status === 404) {
                        throw new AppError(
                            404,
                            'GitHub user not found. Please reconnect your GitHub account.'
                        );
                    }
                    if (error.code === 'ECONNABORTED') {
                        throw new AppError(
                            504,
                            'GitHub API request timeout. Please try again.'
                        );
                    }
                }
                throw new AppError(
                    500,
                    'Failed to fetch repositories from GitHub. Please try again later.'
                );
            }

            // Check if response contains data
            if (
                !userRepositories?.data ||
                !Array.isArray(userRepositories.data)
            ) {
                throw new AppError(500, 'Invalid response from GitHub API');
            }

            // Map repositories to our interface
            const mappedUserRepositories = userRepositories.data
                .filter((repository) => repository !== null) // Remove null entries
                .map((repository: any): Repository => {
                    // Ensure all required fields exist with fallbacks
                    return {
                        id: repository.id || 0,
                        name: repository.name || 'unnamed',
                        full_name: repository.full_name || '',
                        description: repository.description || null,
                        isFork: repository.fork || false,
                        language: repository.language || null,
                        license: repository.license?.name || null,
                        openedIssuesCount: repository.open_issues_count || 0,
                        repoCreatedAt:
                            repository.created_at || new Date().toISOString(),
                        url: repository.url || '',
                    };
                });

            // Check if we have any repositories
            if (mappedUserRepositories.length === 0) {
                throw new AppError(400, 'No repositories found for this user');
            }

            // Sort repositories by creation date (newest first)
            const sortedRepository = mappedUserRepositories.sort(
                (a: Repository, b: Repository) => {
                    try {
                        const dateA = new Date(a.repoCreatedAt).getTime();
                        const dateB = new Date(b.repoCreatedAt).getTime();

                        // Handle invalid dates
                        if (isNaN(dateA) && isNaN(dateB)) return 0;
                        if (isNaN(dateA)) return 1; // Put invalid dates at the end
                        if (isNaN(dateB)) return -1;

                        return dateB - dateA;
                    } catch {
                        return 0; // If date parsing fails, don't change order
                    }
                }
            );

            // Get the most recent repository
            const recentRepository = sortedRepository[0];

            if (!recentRepository) {
                throw new AppError(
                    400,
                    'Unable to determine most recent repository'
                );
            }

            return res(200, { recentRepository });
        } catch (error) {
            // Re-throw AppError instances
            if (error instanceof AppError) {
                throw error;
            }

            // Handle unexpected errors
            console.error('GitHub API Error:', error);
            throw new AppError(
                500,
                'An unexpected error occurred while fetching GitHub repositories'
            );
        }
    }
}

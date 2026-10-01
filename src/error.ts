const defaultErrors = {
    duplicate: {
        code: 'AE001' as const,
        text: 'User already exists'
    },
    suspended: {
        code: 'AE002' as const,
        text: 'User is suspended'
    },
    blacklisted: {
        code: 'AE003' as const,
        text: 'User does not have access'
    },
    invalid: {
        code: 'AE004' as const,
        text: 'User could not be authenticated'
    },
    expired: {
        code: 'IE001' as const,
        text: 'One-time link has expired'
    },
    unexpected: {
        code: 'GE001' as const,
        text: 'An unexpected error occured'
    }
};

type AuthError = keyof typeof defaultErrors;

export type ErrorCode = (typeof defaultErrors)[AuthError]["code"];

export function AuthErrors(errors?: {
    [key in AuthError]: string;
}) {
    const map = { ...defaultErrors };

    if (errors) {
        for (const name in errors) {
            map[name as AuthError].text = errors[name as AuthError];
        }
    }

    return {
        toString(code: ErrorCode) {
            for (const error of Object.values(map)) {
                if (error.code === code) return error.text;
            }

            return map.unexpected.text;
        },
        code(error: AuthError) {
            return map[error].code;
        }
    };
}
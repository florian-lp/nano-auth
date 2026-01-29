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
    unexpected: {
        code: 'GE001' as const,
        text: 'An unexpected error occured'
    }
};

type AuthError = keyof typeof defaultErrors;

export type ErrorCode = (typeof defaultErrors)[AuthError]["code"];

export class AuthErrors {

    errors = defaultErrors;

    constructor(errors?: {
        [key in AuthError]: string;
    }) {
        if (!errors) return;

        for (const name in errors) {
            this.errors[name as AuthError].text = errors[name as AuthError];
        }
    }

    toString(code: ErrorCode) {
        for (const error of Object.values(this.errors)) {
            if (error.code === code) return error.text;
        }

        return this.errors.unexpected.text;
    }

    code(error: AuthError) {
        return this.errors[error].code;
    }

}
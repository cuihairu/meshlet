import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import * as api from './api';
import { ApiError } from './api';

const user: api.SessionUser = {
  user_id: 'u-1',
  email: 'admin@test.local',
  two_factor_required: false,
  two_factor_enabled: true,
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AuthGate two-factor login', () => {
  it('requests a TOTP code when the server requires the second step', async () => {
    vi.spyOn(api.api, 'me').mockRejectedValue(new Error('not signed in'));
    const login = vi
      .spyOn(api.api, 'login')
      .mockResolvedValueOnce({ ...user, two_factor_required: true })
      .mockResolvedValueOnce(user);
    render(<App />);

    // First step: credentials.
    expect(await screen.findByRole('heading', { name: /sign in/i })).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'admin@test.local' },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password-123' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    // Server requires the code — second step appears, no session yet.
    expect(
      await screen.findByRole('heading', { name: /two-factor verification/i }),
    ).toBeTruthy();
    expect(login).toHaveBeenCalledTimes(1);
    expect(login).toHaveBeenLastCalledWith('admin@test.local', 'password-123');

    // Submit the code; second call includes it and signs in.
    fireEvent.change(screen.getByLabelText(/verification code/i), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^verify$/i }));
    await waitFor(() => expect(login).toHaveBeenCalledTimes(2));
    expect(login).toHaveBeenLastCalledWith('admin@test.local', 'password-123', '123456');
  });

  it('shows an invalid-code error when the server returns 401 on a bad code', async () => {
    vi.spyOn(api.api, 'me').mockRejectedValue(new Error('not signed in'));
    const login = vi
      .spyOn(api.api, 'login')
      .mockResolvedValueOnce({ ...user, two_factor_required: true })
      .mockRejectedValueOnce(
        new ApiError(401, 'unauthorized', 'invalid verification code'),
      );
    render(<App />);

    // 等 me() resolve（signed-out）→ 登录表单出现。
    expect(await screen.findByRole('heading', { name: /sign in/i })).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'admin@test.local' },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password-123' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    expect(
      await screen.findByRole('heading', { name: /two-factor verification/i }),
    ).toBeTruthy();

    fireEvent.change(screen.getByLabelText(/verification code/i), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^verify$/i }));
    await waitFor(() => expect(login).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/invalid verification code/i)).toBeTruthy();
    // 仍停留在验证码步骤，不种会话。
    expect(
      await screen.findByRole('heading', { name: /two-factor verification/i }),
    ).toBeTruthy();
  });
});

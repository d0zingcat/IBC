// This file is part of IBC.
// Copyright (C) 2004 Steven M. Kearns (skearns23@yahoo.com )
// Copyright (C) 2004 - 2021 Richard L King (rlking@aultan.com)
// For conditions of distribution and use, see copyright notice in COPYING.txt

// IBC is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// IBC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with IBC.  If not, see <http://www.gnu.org/licenses/>.

package ibcalpha.ibc;

import java.awt.Window;
import java.awt.event.WindowEvent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.ListModel;
import javax.swing.JTextField;

public class SecondFactorAuthenticationDialogHandler implements WindowHandler {
    private SecondFactorAuthenticationDialogHandler() {};
    
    static SecondFactorAuthenticationDialogHandler _secondFactorAuthenticationDialogHandler = new SecondFactorAuthenticationDialogHandler();
    
    static SecondFactorAuthenticationDialogHandler getInstance() {
        return _secondFactorAuthenticationDialogHandler;
    }
    
    @Override
    public boolean filterEvent(Window window, int eventId) {
        switch (eventId) {
            case WindowEvent.WINDOW_OPENED:
                return true;
            case WindowEvent.WINDOW_CLOSED:
                return true;
            default:
                return false;
        }
    }

    @Override
    public void handleWindow(Window window, int eventID) {
        if (eventID == WindowEvent.WINDOW_OPENED) {
            if (LoginManager.loginManager().readonlyLoginRequired()) {
                doReadonlyLogin(window);
            } else if (secondFactorDeviceSelectionRequired(window)) {
                selectSecondFactorDevice(window);
            } else if (totpEnabled(window)) {
                submitTotp(window);
            } else {
                LoginManager.loginManager().setLoginState(LoginManager.LoginState.TWO_FA_IN_PROGRESS);
            }
        } else if (eventID == WindowEvent.WINDOW_CLOSED) {
            if (LoginManager.loginManager().readonlyLoginRequired()) {
                LoginManager.loginManager().setLoginState(LoginManager.LoginState.LOGGED_IN);
                return;
            }
            LoginManager.loginManager().secondFactorAuthenticationDialogClosed();
        }
    }

    @Override
    public boolean recogniseWindow(Window window) {
        // For TWS this window is a JFrame; for Gateway it is a JDialog
        if (! (window instanceof JDialog || window instanceof JFrame)) return false;
        
        return SwingUtils.titleContains(window, "Second Factor Authentication") ||
            SwingUtils.titleContains(window, "Security Code Card Authentication");
    }

    private void doReadonlyLogin(Window window){
        if (SwingUtils.clickButton(window, "Enter Read Only")) {
            Utils.logToConsole("initiating read-only login.");
        } else {
            Utils.logError("could not initiate read-only login.");
        }
    }

    private boolean totpEnabled(Window window) {
        String secret = System.getenv("IBC_TOTP_SECRET");
        return secret != null && !secret.trim().isEmpty()
            && isTotpPrompt(window);
    }

    /**
     * The community ibc-totp fork identifies the post-selection dialog by these
     * labels. Do not submit a TOTP merely because any second-factor dialog has a
     * text field: that could be an IB Key or another authentication method.
     */
    private boolean isTotpPrompt(Window window) {
        return SwingUtils.findLabel(window, "Enter Mobile Authenticator") != null
            || SwingUtils.findLabel(window, "Authenticator app code") != null;
    }

    private void submitTotp(Window window) {
        try {
            JTextField codeField = SwingUtils.findTextField(window, 0);
            if (codeField == null) {
                LoginManager.loginManager().setLoginState(LoginManager.LoginState.TWO_FA_IN_PROGRESS);
                return;
            }
            codeField.setText(Totp.generate(System.getenv("IBC_TOTP_SECRET")));
            if (!SwingUtils.clickButton(window, "OK")) {
                Utils.logError("could not submit TOTP code: OK button not found");
                LoginManager.loginManager().setLoginState(LoginManager.LoginState.TWO_FA_IN_PROGRESS);
                return;
            }
            Utils.logToConsole("TOTP code submitted");
        } catch (RuntimeException error) {
            Utils.logError("could not generate TOTP code: " + error.getMessage());
            LoginManager.loginManager().setLoginState(LoginManager.LoginState.TWO_FA_IN_PROGRESS);
        }
    }
    
    private boolean secondFactorDeviceSelectionRequired(Window window) {
        // this area appears in the Second Factor Authentication dialog when the
        // user has enabled more than one second factor authentication method

        return (SwingUtils.findTextArea(window, "Select second factor device") != null);
    }
    
    private void selectSecondFactorDevice(Window window) {
        JList<?> deviceList = SwingUtils.findList(window, 0);
        if (deviceList == null) {
            Utils.exitWithError(ErrorCodes.CANT_FIND_CONTROL, "could not find second factor device list.");
            return;
        }

        String secondFactorDevice = Settings.settings().getString("SecondFactorDevice", "");
        if (secondFactorDevice.length() == 0) {
            Utils.logError("You should specify the required second factor device using the SecondFactorDevice setting in config.ini");
            return;
        }

        ListModel<?> model = deviceList.getModel();
        for (int i = 0; i < model.getSize(); i++) {
            String entry = model.getElementAt(i).toString().trim();
            if (entry.equals(secondFactorDevice)) {
                deviceList.setSelectedIndex(i);

                if (!SwingUtils.clickButton(window, "OK")) {
                    Utils.logError("could not select second factor device: OK button not found");
                }
                return;
            }
        }
        Utils.logError("could not find second factor device '" + secondFactorDevice + "' in the list");
    }
    
}

/**
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.remoteprovisioner.service;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.security.IGenerateRkpKeyService;
import android.security.remoteprovisioning.AttestationPoolStatus;
import android.security.remoteprovisioning.IRemoteProvisioning;
import android.security.remoteprovisioning.ImplInfo;
import android.util.Log;

import com.android.remoteprovisioner.GeekResponse;
import com.android.remoteprovisioner.PeriodicProvisioner;
import com.android.remoteprovisioner.RemoteProvisioningException;
import com.android.remoteprovisioner.ServerInterface;

import java.time.Duration;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Provides the implementation for IGenerateRkpKeyService.aidl
 */
public class GenerateRkpKeyService extends Service {
    private static final int KEY_GENERATION_PAUSE_MS = 1000;
    private static final Duration LOOKAHEAD_TIME = Duration.ofDays(1);

    private static final String SERVICE = "android.security.remoteprovisioning";
    private static final String TAG = "RemoteProvisioningService";

    private static final ReentrantLock sLock = new ReentrantLock();

    private enum Concurrency {
        BLOCKING,
        NON_BLOCKING
    };

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private final IGenerateRkpKeyService.Stub mBinder = new IGenerateRkpKeyService.Stub() {
        @Override
        public int generateKey(int securityLevel) {
            Log.i(TAG, "generateKey ping for secLevel: " + securityLevel);
            IRemoteProvisioning binder =
                    IRemoteProvisioning.Stub.asInterface(ServiceManager.getService(SERVICE));
            return checkAndFillPool(binder, securityLevel, Concurrency.BLOCKING);
        }

        @Override
        public void notifyKeyGenerated(int securityLevel) {
            Log.i(TAG, "Notify key generated ping for secLevel: " + securityLevel);
            IRemoteProvisioning binder =
                    IRemoteProvisioning.Stub.asInterface(ServiceManager.getService(SERVICE));
            checkAndFillPool(binder, securityLevel, Concurrency.NON_BLOCKING);
        }

        private int checkAndFillPool(IRemoteProvisioning binder, int secLevel,
                Concurrency concurrency) {
            // No need to hammer the pool check with a ton of redundant requests.
            if (concurrency == Concurrency.BLOCKING) {
                Log.i(TAG, "Waiting on lock to check pool status.");
                sLock.lock();
            } else if (!sLock.tryLock()) {
                Log.i(TAG, "Exiting check; another process already started the check.");
                return Status.OK;
            }
            try {
                AttestationPoolStatus pool =
                        binder.getPoolStatus(System.currentTimeMillis(), secLevel);
                ImplInfo[] implInfos = binder.getImplementationInfo();
                int curve = 0;
                for (int i = 0; i < implInfos.length; i++) {
                    if (implInfos[i].secLevel == secLevel) {
                        curve = implInfos[i].supportedCurve;
                        break;
                    }
                }

                Context context = getApplicationContext();
                int keysToProvision =
                        PeriodicProvisioner.generateNumKeysNeeded(binder, context,
                                LOOKAHEAD_TIME.toMillis(),
                                secLevel);
                if (keysToProvision != 0) {
                    Log.i(TAG, "All signed keys are currently in use, provisioning more.");
                    GeekResponse resp = ServerInterface.fetchGeek(context);
                    PeriodicProvisioner.batchProvision(binder, context, keysToProvision, secLevel,
                            resp.getGeekChain(curve), resp.getChallenge());
                }
            } catch (InterruptedException e) {
                Log.e(TAG, "Provisioner thread interrupted.", e);
            } catch (RemoteProvisioningException e) {
                Log.e(TAG, "RemoteProvisioningException: ", e);
                return e.getErrorCode();
            } catch (RemoteException e) {
                Log.e(TAG, "Remote Exception: ", e);
                return Status.INTERNAL_ERROR;
            } finally {
                sLock.unlock();
            }
            return Status.OK;
        }
    };
}

/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.remoteprovisioner.perftest;

import static android.hardware.security.keymint.SecurityLevel.TRUSTED_ENVIRONMENT;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import android.content.Context;
import android.os.ServiceManager;
import android.perftests.utils.BenchmarkState;
import android.perftests.utils.PerfStatusReporter;
import android.security.remoteprovisioning.AttestationPoolStatus;
import android.security.remoteprovisioning.IRemoteProvisioning;
import android.security.remoteprovisioning.ImplInfo;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.runner.AndroidJUnit4;

import com.android.remoteprovisioner.GeekResponse;
import com.android.remoteprovisioner.Provisioner;
import com.android.remoteprovisioner.ProvisionerMetrics;
import com.android.remoteprovisioner.ServerInterface;
import com.android.remoteprovisioner.SettingsManager;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.time.Duration;

@RunWith(AndroidJUnit4.class)
public class ServerToSystemPerfTest {

    private static final String SERVICE = "android.security.remoteprovisioning";

    private static Context sContext;
    private static IRemoteProvisioning sBinder;
    private static int sCurve = 0;

    private Duration mDuration;

    private void assertPoolStatus(int total, int attested,
                                  int unassigned, int expiring, Duration time) throws Exception {
        AttestationPoolStatus pool = sBinder.getPoolStatus(time.toMillis(), TRUSTED_ENVIRONMENT);
        assertEquals(total, pool.total);
        assertEquals(attested, pool.attested);
        assertEquals(unassigned, pool.unassigned);
        assertEquals(expiring, pool.expiring);
    }

    @Rule
    public PerfStatusReporter mPerfStatusReporter = new PerfStatusReporter();

    @BeforeClass
    public static void init() throws Exception {
        sContext = ApplicationProvider.getApplicationContext();
        sBinder =
              IRemoteProvisioning.Stub.asInterface(ServiceManager.getService(SERVICE));
        assertNotNull(sBinder);
        ImplInfo[] info = sBinder.getImplementationInfo();
        for (int i = 0; i < info.length; i++) {
            if (info[i].secLevel == TRUSTED_ENVIRONMENT) {
                sCurve = info[i].supportedCurve;
                break;
            }
        }
    }

    @Before
    public void setUp() throws Exception {
        SettingsManager.clearPreferences(sContext);
        sBinder.deleteAllKeys();
        mDuration = Duration.ofMillis(System.currentTimeMillis());
    }

    @After
    public void tearDown() throws Exception {
        SettingsManager.clearPreferences(sContext);
        sBinder.deleteAllKeys();
    }

    @Test
    public void testFullRoundTrip() throws Exception {
        BenchmarkState state = mPerfStatusReporter.getBenchmarkState();
        while (state.keepRunning()) {
            setUp();
            ProvisionerMetrics metrics = ProvisionerMetrics.createScheduledAttemptMetrics(sContext);
            int numTestKeys = 1;
            sBinder.generateKeyPair(SettingsManager.IS_TEST_MODE, TRUSTED_ENVIRONMENT);
            GeekResponse geek = ServerInterface.fetchGeek(sContext, metrics);
            assertNotNull(geek);
            int numProvisioned =
                    Provisioner.provisionCerts(numTestKeys, TRUSTED_ENVIRONMENT,
                            geek.getGeekChain(sCurve), geek.getChallenge(), sBinder,
                            sContext, metrics);
            assertEquals(numTestKeys, numProvisioned);
            assertPoolStatus(numTestKeys, numTestKeys, numTestKeys, 0, mDuration);
            tearDown();
        }
    }
}

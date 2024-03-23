/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwk;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.jose4j.lang.HashUtil.SHA_256;

import java.util.Arrays;
import java.util.List;

import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 */
@RunWith(Parameterized.class)
public class Rfc7638JwkThumbprintUriTest
{
	private static String PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
	@Parameters(name = "{index}: {0}")
	public static List<Object[]> testCases() {
		return Arrays.asList(
			new Object[] {
		        // http://tools.ietf.org/html/rfc7638#section-3.1
				"rsa-from-rfc-example-3",
				"     {\n" +
                "      \"kty\": \"RSA\",\n" +
                "      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\n" +
                "            VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\n" +
                "            4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\n" +
                "            W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\n" +
                "            1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\n" +
                "            aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "      \"e\": \"AQAB\",\n" +
                "      \"alg\": \"RS256\",\n" +
                "      \"kid\": \"2011-04-29\"\n" +
                "     }",
                SHA_256,
                PREFIX + "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
			},
			new Object[] {
				"oct",
				"{\"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\",\"kty\":\"oct\"}",
				SHA_256,
				PREFIX + "7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g"
			},
			new Object[] {
				"ec-1",
				"{\"crv\":\"P-256\",\"kty\":\"EC\"," +
				"\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
				"\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"}",
				SHA_256,
				PREFIX + "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs"
			},
			new Object[] {
				"ec-2",
				"{\"kty\":\"EC\"," +
				"\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
				"\"crv\":\"P-256\"," +
				"\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"}",
				SHA_256,
				PREFIX + "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs"
			},
			new Object[] {
				"ec-from-nimb",
				"{\"crv\":\"P-256\"," +
	            " \"kty\":\"EC\"," +
	            " \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
	            " \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"}",
	            SHA_256,
	            PREFIX + "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
		    },
			new Object[] {
				"oct-from-nimb",
				"{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}",
				SHA_256,
				PREFIX + "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc"
			},
			// https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
			// ... https://mailarchive.ietf.org/arch/msg/jose/nxct2sTGJvHxtOtofmUA8bMe6B0
			new Object[] {
				"jose-wg-list-test-vector[0]",
				"{\"kty\":\"oct\", \"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\"}",
				SHA_256,
				PREFIX + "7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g"
			},
			new Object[] {
				"jose-wg-list-test-vector[1]",
				"{\"kty\":\"EC\",\n" +
				" \"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\",\n" +
				" \"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\",\n" +
				" \"crv\":\"P-256\"}",
				SHA_256,
				PREFIX + "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs"
			},
			new Object[] {
				"jose-wg-list-test-vector[2]",
				"{\"kty\":\"EC\",\n" +
				" \"x\":\"Aeq3uMrb3iCQEt0PzSeZMmrmYhsKP5DM1oMP6LQzTFQY9-F3Ab45xiK4AJxltXEI-87g3gRwId88hTyHgq180JDt\",\n" +
				" \"y\":\"ARA0lIlrZMEzaXyXE4hjEkc50y_JON3qL7HSae9VuWpOv_2kit8p3pyJBiRb468_U5ztLT7FvDvtimyS42trhDTu\",\n" +
				" \"crv\":\"P-521\"}",
				SHA_256,
				PREFIX + "rz4Ohmpxg-UOWIWqWKHlOe0bHSjNUFlHW5vwG_M7qYg"
			},
			new Object[] {
				"jose-wg-list-test-vector[3]",
				"{\"kty\":\"EC\",\n" +
				" \"x\":\"2jCG5DmKUql9YPn7F2C-0ljWEbj8O8-vn5Ih1k7Wzb-y3NpBLiG1BiRa392b1kcQ\",\n" +
				" \"y\":\"7Ragi9rT-5tSzaMbJlH_EIJl6rNFfj4V4RyFM5U2z4j1hesX5JXa8dWOsE-5wPIl\",\n" +
				" \"crv\":\"P-384\"}",
				SHA_256,
				PREFIX + "vZtaWIw-zw95JNzzURg1YB7mWNLlm44YZDZzhrPNetM"
			},
			new Object[] {
				"jose-wg-list-test-vector[4]",
				"{\"kty\":\"oct\",\"k\":\"NGbwp1rC4n85A1SaNxoHow\"}",
				SHA_256,
				PREFIX + "5_qb56G0OJDw-lb5mkDaWS4MwuY0fatkn9LkNqUHqMk"
			}
		);
	}

	String testCaseName;

	String jwkText;
	String hashAlg;

	String expectedThumbprint;
	String expectedJwkThumbprintUri;

	public Rfc7638JwkThumbprintUriTest(String testCaseName, String jwkText, String hashAlg,
			String expectedJwkThumbprintUri) {
		this.testCaseName = testCaseName;
		this.jwkText = jwkText;
		this.hashAlg = hashAlg;
		this.expectedJwkThumbprintUri = expectedJwkThumbprintUri;
	}

	@Test
	public void testParameterized() throws JoseException {
		JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(jwkText);
		String uri = jsonWebKey.calculateThumbprintUri(hashAlg);
		assertThat(expectedJwkThumbprintUri, equalTo(uri));
	}
}

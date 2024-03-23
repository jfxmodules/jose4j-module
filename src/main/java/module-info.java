/*
 * Copyright 2024 Chad Preisler.
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

/*
 * Copyright 2023 Chad Preisler.
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

module org.jfxmodules.jose4j {
    requires org.slf4j;
    exports org.jose4j.base64url;
    exports org.jose4j.base64url.internal.apache.commons.codec.binary;
    exports org.jose4j.http;
    exports org.jose4j.jca;
    exports org.jose4j.json;
    exports org.jose4j.json.internal.json_simple;
    exports org.jose4j.json.internal.json_simple.parser;
    exports org.jose4j.jwa;
    exports org.jose4j.jwe;
    exports org.jose4j.jwe.kdf;
    exports org.jose4j.jwk;
    exports org.jose4j.jws;
    exports org.jose4j.jwt;
    exports org.jose4j.jwt.consumer;
    exports org.jose4j.jwx;
    exports org.jose4j.keys;
    exports org.jose4j.keys.resolvers;
    exports org.jose4j.lang;
    exports org.jose4j.mac;
    exports org.jose4j.zip;

}
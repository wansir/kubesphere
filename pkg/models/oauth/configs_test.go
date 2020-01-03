/*
 *
 * Copyright 2019 The KubeSphere Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by
applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
*/

package oauth

import (
	"io/ioutil"
)

func prepare() {
	configs := `[{
  "Name": "github",
  "Description": "Sign in with GitHub",
  "Icon": "",
  "ClientID": "8b21fef43889a28f2bd6",
  "Endpoint": {
   "AuthURL": "https://github.com/login/oauth/authorize",
   "TokenURL": "https://github.com/login/oauth/access_token",
   "AuthStyle": 0
  },
  "RedirectURL": "http://localhost:8000/oauth/redirect",
  "Scopes": [
   "user"
  ]
 }]`

	ioutil.WriteFile(configFile, []byte(configs), 0640)
}

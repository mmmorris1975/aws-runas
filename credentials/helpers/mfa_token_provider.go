/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

package helpers

import (
	"fmt"
	"io"
	"os"
)

type mfaTokenProvider struct {
	input io.Reader
}

// NewMfaTokenProvider returns a MfaInputProvider which will read the MFA token information
// from the provided reader.
func NewMfaTokenProvider(in io.Reader) *mfaTokenProvider {
	return &mfaTokenProvider{input: in}
}

// ReadInput gathers the MFA token value in a way which is compatible with the AWS SDK MFA TokenProvider requirements.
// The prompt will be printed on os.Stderr, and the value will be read from the reader supplied with NewMfaTokenProvider.
func (p *mfaTokenProvider) ReadInput() (string, error) {
	var val string

	_, _ = fmt.Fprint(os.Stderr, "MFA token code: ")
	_, err := fmt.Fscanln(p.input, &val)
	if err != nil && err != io.EOF {
		return "", err
	}

	return val, nil
}

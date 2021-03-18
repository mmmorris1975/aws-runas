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

package shared

// Logger is the leveled logging interface used by aws-runas. This will allow us to experiment with
// compatible logging libraries such as:
//   * distillog (https://github.com/amoghe/distillog)
//   * go-logger (https://github.com/apsdehal/go-logger)
//   * alexcesaro/log (https://github.com/alexcesaro/log)
//   * google/logger (https://github.com/google/logger)
//   * simple-logger 0.5.0+ (https://github.com/mmmorris1975/simple-logger) ... my unbiased favorite ;)
//   * other logging frameworks shimmed to comply with the interface requirements
//
// Setup of the concrete logger type will be handled during program initialization.
type Logger interface {
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Warningf(string, ...interface{})
	Errorf(string, ...interface{})
}

// DefaultLogger is a Logger-compatible implementation for use as a fallback/default logger.  It does nothing.
type DefaultLogger bool

// Debugf does nothing.
func (l *DefaultLogger) Debugf(string, ...interface{}) {}

// Infof does nothing.
func (l *DefaultLogger) Infof(string, ...interface{}) {}

// Warningf does nothing.
func (l *DefaultLogger) Warningf(string, ...interface{}) {}

// Errorf does nothing.
func (l *DefaultLogger) Errorf(string, ...interface{}) {}

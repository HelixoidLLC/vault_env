/*
 * Copyright 2016 Igor Moochnick
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

package errors

import (
	"fmt"
	goerrors "github.com/go-errors/errors"
)

// Just a pass-through to the original
func New(e interface{}) *goerrors.Error {
	return goerrors.New(e)
}

// Wrap the given error in an Error type that contains the stack trace. If the given error already has a stack trace,
// it is used directly. If the given error is nil, return nil.
func WithStackTrace(err error) error {
	if err == nil {
		return nil
	}

	return goerrors.Wrap(err, 1)
}

// Wrap the given error in an Error type that contains the stack trace and has the given message prepended as part of
// the error message. If the given error already has a stack trace, it is used directly. If the given error is nil,
// return nil.
func WithStackTraceAndPrefix(err error, message string, args ...interface{}) error {
	if err == nil {
		return nil
	}

	return goerrors.WrapPrefix(err, fmt.Sprintf(message, args...), 1)
}

// Returns true if actual is the same type of error as expected. This method unwraps the given error objects (if they
// are wrapped in objects with a stacktrace) and then does a simple equality check on them.
func IsError(actual error, expected error) bool {
	return goerrors.Is(actual, expected)
}

// If the given error is a wrapper that contains a stacktrace, unwrap it and return the original, underlying error.
// In all other cases, return the error unchanged
func Unwrap(err error) error {
	if err == nil {
		return nil
	}

	goError, isGoError := err.(*goerrors.Error)
	if isGoError {
		return goError.Err
	}

	return err
}

// Convert the given error to a string, including the stack trace if available
func PrintErrorWithStackTrace(err error) string {
	if err == nil {
		return ""
	}

	switch underlyingErr := err.(type) {
	case *goerrors.Error:
		return underlyingErr.ErrorStack()
	default:
		return err.Error()
	}
}

// A method that tries to recover from panics, and if it succeeds, calls the given onPanic function with an error that
// explains the cause of the panic. This function should only be called from a defer statement.
func Recover(onPanic func(cause error)) {
	if rec := recover(); rec != nil {
		err, isError := rec.(error)
		if !isError {
			err = fmt.Errorf("%v", rec)
		}
		onPanic(WithStackTrace(err))
	}
}

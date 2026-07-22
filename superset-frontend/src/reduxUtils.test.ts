/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { areObjectsEqual } from './reduxUtils';

test('returns true for structurally equal objects', () => {
  expect(areObjectsEqual({ a: 1, b: 2 }, { a: 1, b: 2 })).toBe(true);
});

test('returns false for objects with different values', () => {
  expect(areObjectsEqual({ a: 1 }, { a: 2 })).toBe(false);
});

test('compares primitives and arrays', () => {
  expect(areObjectsEqual('a', 'a')).toBe(true);
  expect(areObjectsEqual('a', 'b')).toBe(false);
  expect(areObjectsEqual([1, 2], [1, 2])).toBe(true);
  expect(areObjectsEqual([1, 2], [2, 1])).toBe(false);
});

test('ignoreUndefined skips undefined-valued keys', () => {
  expect(
    areObjectsEqual(
      { a: 1, b: undefined },
      { a: 1 },
      { ignoreUndefined: true },
    ),
  ).toBe(true);
  expect(areObjectsEqual({ a: 1, b: undefined }, { a: 1 })).toBe(false);
});

test('ignoreNull skips null-valued keys', () => {
  expect(
    areObjectsEqual({ a: 1, b: null }, { a: 1 }, { ignoreNull: true }),
  ).toBe(true);
  expect(areObjectsEqual({ a: 1, b: null }, { a: 1 })).toBe(false);
});

test('ignoreFields omits the given fields from the comparison', () => {
  expect(
    areObjectsEqual(
      { a: 1, warning: 'x' },
      { a: 1, warning: 'y' },
      { ignoreFields: ['warning'] },
    ),
  ).toBe(true);
});

test('accepts generically typed arguments without any casts', () => {
  type Slice = { id: number; label: string };
  const left: Slice = { id: 1, label: 'a' };
  const right: Slice = { id: 1, label: 'a' };
  // Purely a compile-time guard: the helper is generic, so both arguments
  // share a single inferred type parameter instead of being `any`.
  const result: boolean = areObjectsEqual<Slice>(left, right);
  expect(result).toBe(true);
});

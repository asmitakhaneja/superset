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

/**
 * Locks the scoped rename of the local ESLint plugin. The unscoped name
 * `eslint-plugin-i18n-strings` collides with the public npm namespace and
 * trips a false-positive critical `npm audit` malware advisory. Renaming it to
 * the org-scoped `@superset-ui/eslint-plugin-i18n-strings` clears the advisory.
 * If the scoped name is reverted this test fails, surfacing the regression.
 */
/* eslint-disable no-template-curly-in-string */
import type { Rule } from 'eslint';

const { RuleTester } = require('eslint');

const pluginPkg: {
  name: string;
} = require('../../eslint-rules/eslint-plugin-i18n-strings/package.json');
const plugin: {
  rules: Record<string, Rule.RuleModule>;
} = require('../../eslint-rules/eslint-plugin-i18n-strings');

test('local i18n-strings plugin keeps its org-scoped name', () => {
  expect(pluginPkg.name).toBe('@superset-ui/eslint-plugin-i18n-strings');
  // A scoped name cannot collide with an unscoped public npm package, which is
  // what the false-positive audit advisory keyed off of.
  expect(pluginPkg.name.startsWith('@')).toBe(true);
});

// `RuleTester.run` registers its own describe/it blocks, so it must be invoked
// at the top level rather than nested inside a `test()`.
const ruleTester = new RuleTester({ languageOptions: { ecmaVersion: 6 } });
const errors = [
  {
    message:
      "Don't use variables in translation string templates. Flask-babel is a static translation service, so it can't handle strings that include variables",
  },
];

ruleTester.run('no-template-vars', plugin.rules['no-template-vars'], {
  valid: ['t(`foo`)', 'tn(`foo %s bar`)'],
  invalid: [
    { code: 't(`foo${bar}`)', errors },
    { code: 'tn(`foo${bar} ${baz}`)', errors },
  ],
});

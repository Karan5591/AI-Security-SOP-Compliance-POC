import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import tseslint from "typescript-eslint";

export default [
  {
    files: ["**/*.js"],
    plugins: { security, "no-unsanitized": noUnsanitized },
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: {
      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "error",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-non-literal-require": "warn",
      "security/detect-pseudoRandomBytes": "error",
      "security/detect-unsafe-regex": "error",
      "security/detect-possible-timing-attacks": "warn",
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
    },
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { ecmaVersion: "latest", sourceType: "module" },
    },
    plugins: { security, "no-unsanitized": noUnsanitized },
    rules: {
      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "error",
      "security/detect-pseudoRandomBytes": "error",
      "security/detect-unsafe-regex": "error",
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
    },
  },
];

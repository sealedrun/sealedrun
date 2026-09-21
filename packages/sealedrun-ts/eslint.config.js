import js from "@eslint/js";
import jsdoc from "eslint-plugin-jsdoc";
import tsdoc from "eslint-plugin-tsdoc";
import tseslint from "typescript-eslint";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.strict,
  { ignores: ["dist/**"] },
  {
    files: ["src/**"],
    plugins: { jsdoc, tsdoc },
    rules: {
      "tsdoc/syntax": "error",
      "jsdoc/require-jsdoc": [
        "error",
        {
          publicOnly: true,
          contexts: ["TSInterfaceDeclaration", "TSTypeAliasDeclaration"],
          require: { ClassDeclaration: true, FunctionDeclaration: true, MethodDefinition: true },
        },
      ],
    },
  },
  { files: ["test/**"], rules: { "@typescript-eslint/no-non-null-assertion": "off" } },
);

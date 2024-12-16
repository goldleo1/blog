<<<<<<< HEAD
import sitemap from '@astrojs/sitemap';
import svelte from "@astrojs/svelte"
import tailwind from "@astrojs/tailwind"
import swup from '@swup/astro';
import Compress from "astro-compress"
import icon from "astro-icon"
import { defineConfig } from "astro/config"
import Color from "colorjs.io"
import rehypeAutolinkHeadings from "rehype-autolink-headings"
import rehypeComponents from "rehype-components"; /* Render the custom directive content */
import rehypeKatex from "rehype-katex"
import rehypeSlug from "rehype-slug"
import remarkDirective from "remark-directive" /* Handle directives */
import remarkGithubAdmonitionsToDirectives from "remark-github-admonitions-to-directives";
import remarkMath from "remark-math"
import { AdmonitionComponent } from "./src/plugins/rehype-component-admonition.mjs"
import { GithubCardComponent } from "./src/plugins/rehype-component-github-card.mjs"
import {parseDirectiveNode} from "./src/plugins/remark-directive-rehype.js";
import { remarkReadingTime } from "./src/plugins/remark-reading-time.mjs"
import {remarkExcerpt} from "./src/plugins/remark-excerpt.js";

const oklchToHex = (str) => {
  const DEFAULT_HUE = 250
  const regex = /-?\d+(\.\d+)?/g
  const matches = str.string.match(regex)
  const lch = [matches[0], matches[1], DEFAULT_HUE]
  return new Color("oklch", lch).to("srgb").toString({
    format: "hex",
  })
}
=======
import sitemap from "@astrojs/sitemap";
import svelte from "@astrojs/svelte";
import tailwind from "@astrojs/tailwind";
import swup from "@swup/astro";
import Compress from "astro-compress";
import icon from "astro-icon";
import { defineConfig } from "astro/config";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypeComponents from "rehype-components"; /* Render the custom directive content */
import rehypeKatex from "rehype-katex";
import rehypeSlug from "rehype-slug";
import remarkDirective from "remark-directive"; /* Handle directives */
import remarkGithubAdmonitionsToDirectives from "remark-github-admonitions-to-directives";
import remarkMath from "remark-math";
import remarkSectionize from "remark-sectionize";
import { AdmonitionComponent } from "./src/plugins/rehype-component-admonition.mjs";
import { GithubCardComponent } from "./src/plugins/rehype-component-github-card.mjs";
import { parseDirectiveNode } from "./src/plugins/remark-directive-rehype.js";
import { remarkExcerpt } from "./src/plugins/remark-excerpt.js";
import { remarkReadingTime } from "./src/plugins/remark-reading-time.mjs";
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1

// https://astro.build/config
export default defineConfig({
  site: "https://github.github.io",
  base: "/",
  trailingSlash: "always",
  integrations: [
<<<<<<< HEAD
    tailwind(),
    swup({
      theme: false,
      animationClass: 'transition-swup-',   // see https://swup.js.org/options/#animationselector
                                            // the default value `transition-` cause transition delay
                                            // when the Tailwind class `transition-all` is used
      containers: ['main'],
=======
    tailwind(
        {
          nesting: true,
        }
    ),
    swup({
      theme: false,
      animationClass: "transition-swup-", // see https://swup.js.org/options/#animationselector
      // the default value `transition-` cause transition delay
      // when the Tailwind class `transition-all` is used
      containers: ["main", "#toc"],
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1
      smoothScrolling: true,
      cache: true,
      preload: true,
      accessibility: true,
      updateHead: true,
      updateBodyClass: false,
      globalInstance: true,
    }),
    icon({
      include: {
<<<<<<< HEAD
        "material-symbols": ["*"],
=======
        "preprocess: vitePreprocess(),": ["*"],
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1
        "fa6-brands": ["*"],
        "fa6-regular": ["*"],
        "fa6-solid": ["*"],
      },
    }),
    svelte(),
    sitemap(),
    Compress({
      CSS: false,
      Image: false,
      Action: {
<<<<<<< HEAD
        Passed: async () => true,   // https://github.com/PlayForm/Compress/issues/376
=======
        Passed: async () => true, // https://github.com/PlayForm/Compress/issues/376
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1
      },
    }),
  ],
  markdown: {
<<<<<<< HEAD
    remarkPlugins: [remarkMath, remarkReadingTime, remarkExcerpt, remarkGithubAdmonitionsToDirectives, remarkDirective, parseDirectiveNode],
    rehypePlugins: [
      rehypeKatex,
      rehypeSlug,
      [rehypeComponents, {
        components: {
          github: GithubCardComponent,
          note: (x, y) => AdmonitionComponent(x, y, "note"),
          tip: (x, y) => AdmonitionComponent(x, y, "tip"),
          important: (x, y) => AdmonitionComponent(x, y, "important"),
          caution: (x, y) => AdmonitionComponent(x, y, "caution"),
          warning: (x, y) => AdmonitionComponent(x, y, "warning"),
        },
      }],
=======
    remarkPlugins: [
      remarkMath,
      remarkReadingTime,
      remarkExcerpt,
      remarkGithubAdmonitionsToDirectives,
      remarkDirective,
      remarkSectionize,
      parseDirectiveNode,
    ],
    rehypePlugins: [
      rehypeKatex,
      rehypeSlug,
      [
        rehypeComponents,
        {
          components: {
            github: GithubCardComponent,
            note: (x, y) => AdmonitionComponent(x, y, "note"),
            tip: (x, y) => AdmonitionComponent(x, y, "tip"),
            important: (x, y) => AdmonitionComponent(x, y, "important"),
            caution: (x, y) => AdmonitionComponent(x, y, "caution"),
            warning: (x, y) => AdmonitionComponent(x, y, "warning"),
          },
        },
      ],
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1
      [
        rehypeAutolinkHeadings,
        {
          behavior: "append",
          properties: {
            className: ["anchor"],
          },
          content: {
            type: "element",
            tagName: "span",
            properties: {
              className: ["anchor-icon"],
<<<<<<< HEAD
              'data-pagefind-ignore': true,
=======
              "data-pagefind-ignore": true,
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1
            },
            children: [
              {
                type: "text",
                value: "#",
              },
            ],
          },
        },
      ],
    ],
  },
  vite: {
    build: {
      rollupOptions: {
        onwarn(warning, warn) {
          // temporarily suppress this warning
<<<<<<< HEAD
          if (warning.message.includes("is dynamically imported by") && warning.message.includes("but also statically imported by")) {
            return;
          }
          warn(warning);
        }
      }
    },
    css: {
      preprocessorOptions: {
        stylus: {
          define: {
            oklchToHex: oklchToHex,
          },
=======
          if (
            warning.message.includes("is dynamically imported by") &&
            warning.message.includes("but also statically imported by")
          ) {
            return;
          }
          warn(warning);
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1
        },
      },
    },
  },
<<<<<<< HEAD
})
=======
});
>>>>>>> 9105ad7dff2fdfd9df64929ca5f6e364141784b1

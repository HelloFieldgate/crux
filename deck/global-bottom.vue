<script setup>
import { useNav } from '@slidev/client'
const { next, prev, hasNext, hasPrev } = useNav()
</script>

<template>
  <button v-if="hasPrev" class="slide-nav slide-nav-left" @click="prev">&lt;</button>
  <button v-if="hasNext" class="slide-nav slide-nav-right" @click="next">&gt;</button>
</template>

<style scoped>
.slide-nav {
  position: fixed;
  top: 50%;
  transform: translateY(-50%);
  background: transparent;
  border: none;
  color: rgba(255, 255, 255, 0.15);
  font-size: 2.5rem;
  font-weight: 200;
  cursor: pointer;
  padding: 1.5rem 1rem;
  z-index: 200;
  line-height: 1;
  user-select: none;
  transition: color 0.2s;
}
.slide-nav:hover {
  color: rgba(255, 255, 255, 0.45);
}
.slide-nav-left  { left: 0; }
.slide-nav-right { right: 0; }
</style>

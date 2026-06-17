/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Edge } from '@xyflow/react';
import { CustomNginxNode } from '../types';

/**
 * Estimated height of each node type to prevent overlaps when expanded or containing data.
 */
export const getNodeHeight = (node: CustomNginxNode): number => {
  const t = node.type;
  if (t === 'server') return 420;
  if (t === 'location') return 450;
  if (t === 'upstream') return 420;
  if (t === 'global_core') return 280;
  if (t === 'global_http') return 320;
  if (t === 'global_gzip') return 340;
  if (t === 'global_stream') return 250;
  if (t === 'custom_module') return 385;
  if (t === 'raw_config') return 400;
  return 280; // safe default
};

/**
 * Estimated width of each node type.
 */
export const getNodeWidth = (node: CustomNginxNode): number => {
  const t = node.type;
  if (t === 'upstream') return 320;
  if (t === 'custom_module') return 320;
  if (t === 'raw_config') return 320;
  return 288;
};

/**
 * Determines logical parent/child relationship between source and target nodes based on their type.
 * Custom modules and raw configuration blocks act as children to their parent contexts (server, location, global blocks).
 */
export const getLogicalParentChild = (
  sourceId: string,
  targetId: string,
  nodes: CustomNginxNode[]
): { parentId: string; childId: string } => {
  const sourceNode = nodes.find(n => n.id === sourceId);
  const targetNode = nodes.find(n => n.id === targetId);
  
  if (!sourceNode || !targetNode) {
    return { parentId: sourceId, childId: targetId };
  }

  const isChildType = (type?: string) => type === 'custom_module' || type === 'raw_config';
  
  const isChildA = isChildType(sourceNode.type);
  const isChildB = isChildType(targetNode.type);
  
  if (isChildA && !isChildB) {
    // Source is child (e.g. raw_config), Target is parent (e.g. server). Invert hierarchy relationship.
    return { parentId: targetId, childId: sourceId };
  }
  if (!isChildA && isChildB) {
    // Source is parent (e.g. server), Target is child (e.g. raw_config). Normal hierarchy relationship.
    return { parentId: sourceId, childId: targetId };
  }
  
  // Otherwise keep default React Flow edge direction (source -> target)
  return { parentId: sourceId, childId: targetId };
};

/**
 * Arranges canvas nodes in a clean DAG layout from left-to-right.
 * Resolves levels dynamically using cycle-safe DFS and stacks nodes vertically with spacing margins.
 */
export const arrangeNodes = (nodes: CustomNginxNode[], edges: Edge[]): CustomNginxNode[] => {
  if (nodes.length === 0) return nodes;

  // 1. Build adjacency maps
  const childrenMap = new Map<string, string[]>();
  const parentsMap = new Map<string, string[]>();
  
  nodes.forEach(n => {
    childrenMap.set(n.id, []);
    parentsMap.set(n.id, []);
  });

  edges.forEach(e => {
    const { parentId, childId } = getLogicalParentChild(e.source, e.target, nodes);
    if (childrenMap.has(parentId) && childrenMap.has(childId)) {
      childrenMap.get(parentId)!.push(childId);
    }
    if (parentsMap.has(childId) && parentsMap.has(parentId)) {
      parentsMap.get(childId)!.push(parentId);
    }
  });

  // 2. DFS to compute levels with cycle detection and memoization
  const levels = new Map<string, number>();
  const path = new Set<string>();
  const memo = new Map<string, number>();

  const getLevel = (nodeId: string): number => {
    if (memo.has(nodeId)) return memo.get(nodeId)!;
    if (path.has(nodeId)) return 0; // Cycle safety
    
    path.add(nodeId);
    
    const parents = parentsMap.get(nodeId) || [];
    let maxParentLevel = -1;
    parents.forEach(pId => {
      const lvl = getLevel(pId);
      if (lvl > maxParentLevel) {
        maxParentLevel = lvl;
      }
    });
    
    path.delete(nodeId);
    
    const resolvedLevel = maxParentLevel + 1;
    memo.set(nodeId, resolvedLevel);
    return resolvedLevel;
  };

  nodes.forEach(n => {
    levels.set(n.id, getLevel(n.id));
  });

  // 3. Group nodes by level
  let maxLevel = 0;
  levels.forEach(lvl => {
    if (lvl > maxLevel) maxLevel = lvl;
  });

  const levelGroups: CustomNginxNode[][] = Array.from({ length: maxLevel + 1 }, () => []);
  nodes.forEach(n => {
    const lvl = levels.get(n.id) || 0;
    levelGroups[lvl].push(n);
  });

  // 4. Position parameters
  const columnWidth = 440; // width + gap
  const verticalGap = 100; // Separation gap between nodes in the same column
  const colXOffset = 50;
  const colYOffset = 50;

  const positionedNodes = [...nodes];
  const posRegistry = new Map<string, { x: number; y: number }>();

  const typePriority = (type?: string) => {
    if (type === 'global_core' || type === 'server') return 0;
    if (type === 'global_http' || type === 'location') return 1;
    if (type === 'global_gzip' || type === 'upstream') return 2;
    if (type === 'global_stream' || type === 'custom_module') return 3;
    return 4; // raw_config, etc.
  };

  // Process Level 0 (Roots)
  levelGroups[0].sort((a, b) => typePriority(a.type) - typePriority(b.type));
  let currentY0 = colYOffset;
  levelGroups[0].forEach(n => {
    const x = colXOffset;
    const y = currentY0;
    posRegistry.set(n.id, { x, y });
    
    const idx = positionedNodes.findIndex(node => node.id === n.id);
    if (idx !== -1) {
      positionedNodes[idx] = {
        ...positionedNodes[idx],
        position: { x, y }
      };
    }
    currentY0 += getNodeHeight(n) + verticalGap;
  });

  // Process subsequent levels using parent barycenter sorting
  for (let lvl = 1; lvl <= maxLevel; lvl++) {
    const group = levelGroups[lvl];
    if (group.length === 0) continue;

    group.sort((a, b) => {
      const parentsA = parentsMap.get(a.id) || [];
      const parentsB = parentsMap.get(b.id) || [];
      
      const getAvgParentY = (pIds: string[]) => {
        if (pIds.length === 0) return 0;
        let sum = 0;
        let count = 0;
        pIds.forEach(id => {
          const pos = posRegistry.get(id);
          if (pos) {
            sum += pos.y;
            count++;
          }
        });
        return count > 0 ? sum / count : 0;
      };

      const avgYA = getAvgParentY(parentsA);
      const avgYB = getAvgParentY(parentsB);
      
      if (avgYA !== avgYB) return avgYA - avgYB;
      return typePriority(a.type) - typePriority(b.type);
    });

    let currentY = colYOffset;
    const colX = colXOffset + lvl * columnWidth;

    group.forEach(n => {
      const x = colX;
      const y = currentY;
      posRegistry.set(n.id, { x, y });

      const idx = positionedNodes.findIndex(node => node.id === n.id);
      if (idx !== -1) {
        positionedNodes[idx] = {
          ...positionedNodes[idx],
          position: { x, y }
        };
      }
      currentY += getNodeHeight(n) + verticalGap;
    });
  }

  return positionedNodes;
};

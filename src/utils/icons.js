/**
 * Lightweight inline-SVG icon renderer built on top of the `lucide` icon
 * data package (already a dependency - no extra runtime/CDN fetch).
 * Icons are rendered directly to markup strings so they can be embedded in
 * the template-string based views used throughout this app.
 */
import SearchIcon from 'lucide/dist/esm/icons/search.js';
import XIcon from 'lucide/dist/esm/icons/x.js';
import SunIcon from 'lucide/dist/esm/icons/sun.js';
import MoonIcon from 'lucide/dist/esm/icons/moon.js';
import ShieldIcon from 'lucide/dist/esm/icons/shield.js';
import ShieldCheckIcon from 'lucide/dist/esm/icons/shield-check.js';
import ShieldAlertIcon from 'lucide/dist/esm/icons/shield-alert.js';
import AlertTriangleIcon from 'lucide/dist/esm/icons/alert-triangle.js';
import CopyIcon from 'lucide/dist/esm/icons/copy.js';
import CopyCheckIcon from 'lucide/dist/esm/icons/copy-check.js';
import CheckCircleIcon from 'lucide/dist/esm/icons/check-circle.js';
import XCircleIcon from 'lucide/dist/esm/icons/x-circle.js';
import BookmarkIcon from 'lucide/dist/esm/icons/bookmark.js';
import BookmarkCheckIcon from 'lucide/dist/esm/icons/bookmark-check.js';
import ChevronDownIcon from 'lucide/dist/esm/icons/chevron-down.js';
import ListChecksIcon from 'lucide/dist/esm/icons/list-checks.js';
import TicketCheckIcon from 'lucide/dist/esm/icons/ticket-check.js';
import CodeIcon from 'lucide/dist/esm/icons/code.js';
import GaugeIcon from 'lucide/dist/esm/icons/gauge.js';
import TargetIcon from 'lucide/dist/esm/icons/target.js';
import ScaleIcon from 'lucide/dist/esm/icons/scale.js';
import InfoIcon from 'lucide/dist/esm/icons/info.js';
import LayersIcon from 'lucide/dist/esm/icons/layers.js';
import Link2Icon from 'lucide/dist/esm/icons/link-2.js';
import DatabaseIcon from 'lucide/dist/esm/icons/database.js';
import WifiOffIcon from 'lucide/dist/esm/icons/wifi-off.js';
import CloudIcon from 'lucide/dist/esm/icons/cloud.js';

function attrsToString(attrs) {
  return Object.keys(attrs)
    .map((key) => `${key}="${String(attrs[key])}"`)
    .join(' ');
}

function nodeToString([tag, attrs, children = []]) {
  const inner = children.map(nodeToString).join('');
  return `<${tag} ${attrsToString(attrs)}>${inner}</${tag}>`;
}

/**
 * Renders a lucide icon-data tuple to an inline SVG markup string.
 * @param {Array} iconData - the [tag, attrs, children] tuple exported by a lucide icon module
 * @param {{size?: number, className?: string, strokeWidth?: number}} options
 */
export function icon(iconData, { size = 16, className = '', strokeWidth } = {}) {
  const [tag, baseAttrs, children] = iconData;
  const attrs = {
    ...baseAttrs,
    width: size,
    height: size,
    class: `icon${className ? ' ' + className : ''}`
  };
  if (strokeWidth) attrs['stroke-width'] = strokeWidth;
  return nodeToString([tag, attrs, children]);
}

export const Icons = {
  search: SearchIcon,
  x: XIcon,
  sun: SunIcon,
  moon: MoonIcon,
  shield: ShieldIcon,
  shieldCheck: ShieldCheckIcon,
  shieldAlert: ShieldAlertIcon,
  alertTriangle: AlertTriangleIcon,
  copy: CopyIcon,
  copyCheck: CopyCheckIcon,
  checkCircle: CheckCircleIcon,
  xCircle: XCircleIcon,
  bookmark: BookmarkIcon,
  bookmarkCheck: BookmarkCheckIcon,
  chevronDown: ChevronDownIcon,
  listChecks: ListChecksIcon,
  ticketCheck: TicketCheckIcon,
  code: CodeIcon,
  gauge: GaugeIcon,
  target: TargetIcon,
  scale: ScaleIcon,
  info: InfoIcon,
  layers: LayersIcon,
  link2: Link2Icon,
  database: DatabaseIcon,
  wifiOff: WifiOffIcon,
  cloud: CloudIcon
};

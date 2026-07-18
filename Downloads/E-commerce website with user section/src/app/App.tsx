import { useState, useRef, useEffect } from "react";
import {
  ShoppingCart, User, Menu, X, Search, Heart, Star, Package,
  ArrowLeft, RotateCcw, Settings, Users, Store, LogOut, Home,
  ShoppingBag, Eye, Edit, Trash2, Plus, DollarSign, Check,
  Bell, Truck, MapPin, CreditCard, Tag, Smartphone, Banknote,
  Building2, BarChart2, TrendingUp, AlertTriangle, FileText,
  CheckCircle, Award, Globe, Leaf, ChevronRight, ChevronLeft,
  Printer, ChevronDown, SlidersHorizontal, Upload, Percent,
  Ticket, Gift, RefreshCw, Clock, MessageCircle, Phone,
  HelpCircle, Zap, Shield
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Product {
  id: number; name: string; price: number; originalPrice?: number;
  category: string; rating: number; reviews: number; image: string;
  description: string; vendor: string; stock: number; badge?: string;
}
interface CartItem { product: Product; qty: number; }
interface OrderItem { name: string; qty: number; price: number; image: string; }
interface Order {
  id: string; date: string; status: "delivered" | "processing" | "shipped" | "cancelled";
  total: number; items: OrderItem[]; address: string; tracking?: string;
}
interface Vendor {
  id: number; name: string; store: string; products: number; sales: number;
  revenue: number; rating: number; status: "active" | "pending" | "suspended"; joined: string;
}
interface Coupon {
  id: number; code: string; discount: number; type: "percent" | "flat";
  scope: string; expires: string; uses: number; active: boolean;
}
interface UserProfile { firstName: string; email: string; role: "user" | "vendor" | "admin"; points: number; }
interface SavedAddress { id: number; label: string; name: string; street: string; city: string; state: string; pincode: string; phone: string; isDefault: boolean; }
interface SavedPayment { id: number; type: "card" | "upi"; label: string; isDefault: boolean; }

// ─── Mock Data ────────────────────────────────────────────────────────────────

const ALL_PRODUCTS: Product[] = [
  { id: 1, name: "Heritage Leather Messenger", price: 189, originalPrice: 240, category: "Bags", rating: 4.8, reviews: 124, vendor: "Artisan Goods Co.", image: "https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=600&h=600&fit=crop&auto=format", description: "Full-grain vegetable-tanned leather messenger bag with solid brass hardware and waxed cotton canvas lining. Fits a 15\" laptop comfortably.", stock: 12, badge: "Sale" },
  { id: 2, name: "Ceramic Pour-Over Set", price: 78, category: "Home", rating: 4.9, reviews: 89, vendor: "Kilnworks Studio", image: "https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=600&h=600&fit=crop&auto=format", description: "Handthrown ceramic pour-over dripper with a matching 300ml mug. Every piece is unique with subtle glaze variations from the wood-firing process.", stock: 8, badge: "Bestseller" },
  { id: 3, name: "Merino Wool Overshirt", price: 145, category: "Apparel", rating: 4.7, reviews: 203, vendor: "Nordic Wool Co.", image: "https://images.unsplash.com/photo-1602810318383-e386cc2a3ccf?w=600&h=600&fit=crop&auto=format", description: "Extra-fine 17.5-micron merino wool overshirt in a relaxed silhouette. Naturally temperature-regulating, odor-resistant, and machine washable.", stock: 25 },
  { id: 4, name: "Walnut Desk Organizer", price: 95, category: "Home", rating: 4.6, reviews: 67, vendor: "Grain & Form", image: "https://images.unsplash.com/photo-1593642533144-3d62aa4783ec?w=600&h=600&fit=crop&auto=format", description: "CNC-machined solid black walnut desk organizer with sections for pens, cards, and small accessories. Finished with food-safe tung oil.", stock: 6, badge: "New" },
  { id: 5, name: "Hand-dyed Silk Scarf", price: 120, originalPrice: 160, category: "Accessories", rating: 4.9, reviews: 41, vendor: "Hana Textiles", image: "https://images.unsplash.com/photo-1601924638867-3a6de6b7a500?w=600&h=600&fit=crop&auto=format", description: "100% habotai silk scarf individually hand-dyed using botanical dyes from Japanese indigo, weld, and madder root. 90 × 90cm.", stock: 15, badge: "Sale" },
  { id: 6, name: "Seasoned Cast Iron Skillet", price: 65, category: "Kitchen", rating: 4.8, reviews: 312, vendor: "Foundry Works", image: "https://images.unsplash.com/photo-1544441454-5a93cde473b0?w=600&h=600&fit=crop&auto=format", description: "10-inch cast iron skillet pre-seasoned with organic flaxseed oil. Compatible with all stovetops including induction. Oven-safe to 700°F.", stock: 40 },
  { id: 7, name: "Leather Card Wallet", price: 45, category: "Accessories", rating: 4.5, reviews: 178, vendor: "Artisan Goods Co.", image: "https://images.unsplash.com/photo-1627123424574-724758594e93?w=600&h=600&fit=crop&auto=format", description: "Slim minimalist card wallet in full-grain Horween leather. Holds 4–8 cards plus folded cash. Ages beautifully with use.", stock: 30 },
  { id: 8, name: "Stonewashed Linen Throw", price: 88, category: "Home", rating: 4.7, reviews: 95, vendor: "Coastal Linen Co.", image: "https://images.unsplash.com/photo-1590490360182-c33d57733427?w=600&h=600&fit=crop&auto=format", description: "Belgian linen throw in herringbone weave, stonewashed for immediate softness. Gets softer with every wash. 130 × 170cm.", stock: 18, badge: "New" },
  { id: 9, name: "Linen Table Runner", price: 52, category: "Home", rating: 4.6, reviews: 73, vendor: "Coastal Linen Co.", image: "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=600&h=600&fit=crop&auto=format", description: "Stonewashed linen table runner in natural undyed flax, hemstitched edges. 40 × 150cm. Gets more beautiful with each wash.", stock: 22 },
  { id: 10, name: "Japanese Whetstone Set", price: 85, category: "Kitchen", rating: 4.9, reviews: 156, vendor: "Foundry Works", image: "https://images.unsplash.com/photo-1617713964959-d9a36bbc7551?w=600&h=600&fit=crop&auto=format", description: "Double-sided 1000/6000 grit whetstone with bamboo base and flattening stone. Restores any blade to razor sharpness.", stock: 14 },
  { id: 11, name: "Beeswax Pillar Candles", price: 38, category: "Home", rating: 4.7, reviews: 44, vendor: "Kilnworks Studio", image: "https://images.unsplash.com/photo-1608181831718-c9fca6b1d11c?w=600&h=600&fit=crop&auto=format", description: "Pure beeswax pillar candles, naturally honey-scented. Burns 60+ hours. Set of 3 in graduated heights.", stock: 35, badge: "New" },
  { id: 12, name: "Cork Yoga Blocks", price: 42, category: "Accessories", rating: 4.5, reviews: 89, vendor: "Nordic Wool Co.", image: "https://images.unsplash.com/photo-1599901860904-17e6ed7083a0?w=600&h=600&fit=crop&auto=format", description: "Natural Portuguese cork yoga blocks, sustainably harvested. Firm, non-slip, biodegradable. Set of 2.", stock: 28 },
  { id: 13, name: "Brass Sundial Compass", price: 128, originalPrice: 165, category: "Accessories", rating: 4.8, reviews: 32, vendor: "Grain & Form", image: "https://images.unsplash.com/photo-1529339944280-62e3e9e769b1?w=600&h=600&fit=crop&auto=format", description: "Solid brass pocket compass with sundial and relief-engraved compass rose. Presented in a handmade walnut case.", stock: 7, badge: "Sale" },
  { id: 14, name: "Handwoven Market Tote", price: 72, category: "Bags", rating: 4.7, reviews: 118, vendor: "Hana Textiles", image: "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=600&h=600&fit=crop&auto=format", description: "Hand-woven natural seagrass market tote with leather handles. Fully lined with organic cotton. Holds up to 15kg.", stock: 11 },
  { id: 15, name: "End-grain Serving Board", price: 115, category: "Kitchen", rating: 4.9, reviews: 201, vendor: "Grain & Form", image: "https://images.unsplash.com/photo-1585664811087-47f65abbad64?w=600&h=600&fit=crop&auto=format", description: "End-grain maple and walnut cutting board, finished with beeswax. Self-healing surface that's gentle on knife edges. 30 × 45cm.", stock: 9, badge: "Bestseller" },
  { id: 16, name: "Alpaca Wool Blanket", price: 195, originalPrice: 240, category: "Home", rating: 4.8, reviews: 67, vendor: "Nordic Wool Co.", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=600&h=600&fit=crop&auto=format", description: "100% baby alpaca woven blanket from Andean highlands. Naturally hypoallergenic, warmer than merino, lighter than cashmere. 130 × 180cm.", stock: 5, badge: "Sale" },
  { id: 17, name: "Leather Field Journal", price: 68, category: "Accessories", rating: 4.6, reviews: 143, vendor: "Artisan Goods Co.", image: "https://images.unsplash.com/photo-1531346878377-a5be20888e57?w=600&h=600&fit=crop&auto=format", description: "A5 field journal bound in full-grain vegetable-tanned leather with lay-flat binding, acid-free paper, and a brass clasp.", stock: 20 },
  { id: 18, name: "Hammered Copper Mugs", price: 58, category: "Kitchen", rating: 4.7, reviews: 94, vendor: "Foundry Works", image: "https://images.unsplash.com/photo-1509042239860-f550ce710b93?w=600&h=600&fit=crop&auto=format", description: "Set of 2 hand-hammered pure copper Moscow Mule mugs. Naturally antimicrobial. Brass handles. Each piece slightly unique.", stock: 16, badge: "New" },
];

const ORDERS_INIT: Order[] = [
  { id: "ORD-2025-0943", date: "July 3, 2025", status: "shipped", total: 145, items: [{ name: "Merino Wool Overshirt", qty: 1, price: 145, image: ALL_PRODUCTS[2].image }], address: "42 Maple Street, Portland OR 97201", tracking: "1Z999AA10123457899" },
  { id: "ORD-2025-0892", date: "June 28, 2025", status: "delivered", total: 234, items: [{ name: "Heritage Leather Messenger", qty: 1, price: 189, image: ALL_PRODUCTS[0].image }, { name: "Leather Card Wallet", qty: 1, price: 45, image: ALL_PRODUCTS[6].image }], address: "42 Maple Street, Portland OR 97201", tracking: "1Z999AA10123456784" },
  { id: "ORD-2025-0751", date: "May 14, 2025", status: "delivered", total: 78, items: [{ name: "Ceramic Pour-Over Set", qty: 1, price: 78, image: ALL_PRODUCTS[1].image }], address: "42 Maple Street, Portland OR 97201", tracking: "1Z999AA10123456121" },
  { id: "ORD-2025-1001", date: "July 10, 2025", status: "processing", total: 183, items: [{ name: "Walnut Desk Organizer", qty: 1, price: 95, image: ALL_PRODUCTS[3].image }, { name: "Stonewashed Linen Throw", qty: 1, price: 88, image: ALL_PRODUCTS[7].image }], address: "42 Maple Street, Portland OR 97201" },
];

const VENDORS: Vendor[] = [
  { id: 1, name: "Marcus Holloway", store: "Artisan Goods Co.", products: 24, sales: 1823, revenue: 98420, rating: 4.8, status: "active", joined: "Mar 2023" },
  { id: 2, name: "Yuki Tanaka", store: "Kilnworks Studio", products: 12, sales: 654, revenue: 41200, rating: 4.9, status: "active", joined: "Jun 2023" },
  { id: 3, name: "Erik Lindqvist", store: "Nordic Wool Co.", products: 18, sales: 2104, revenue: 187300, rating: 4.7, status: "active", joined: "Jan 2023" },
  { id: 4, name: "James Okafor", store: "Grain & Form", products: 8, sales: 321, revenue: 22100, rating: 4.6, status: "pending", joined: "Jul 2025" },
  { id: 5, name: "Hana Miyamoto", store: "Hana Textiles", products: 31, sales: 489, revenue: 44800, rating: 4.9, status: "active", joined: "Feb 2024" },
  { id: 6, name: "Robert Chen", store: "Foundry Works", products: 6, sales: 2890, revenue: 134500, rating: 4.8, status: "active", joined: "Nov 2022" },
];

const COUPONS_INIT: Coupon[] = [
  { id: 1, code: "WELCOME10", discount: 10, type: "percent", scope: "all", expires: "2025-12-31", uses: 142, active: true },
  { id: 2, code: "SUMMER20", discount: 20, type: "percent", scope: "Apparel", expires: "2025-08-31", uses: 67, active: true },
  { id: 3, code: "FLAT500", discount: 500, type: "flat", scope: "all", expires: "2025-09-15", uses: 23, active: false },
];

const PRODUCT_ORDER_COUNTS: Record<number, number> = { 1: 189, 2: 312, 3: 467, 4: 89, 5: 41, 6: 891, 7: 234, 8: 156, 9: 78, 10: 134, 11: 55, 12: 91, 13: 29, 14: 103, 15: 198, 16: 61, 17: 142, 18: 87 };

// ─── Helpers ──────────────────────────────────────────────────────────────────

type Page = "shop" | "product" | "hub" | "account" | "vendor" | "admin" | "login" | "payment" | "confirmed" | "our-story";
type AccTab = "overview" | "orders" | "order-detail" | "profile" | "addresses" | "wishlist-alerts" | "recently-viewed" | "loyalty" | "returns" | "settings" | "help";
type AdminTab = "overview" | "vendors" | "products" | "users" | "orders" | "commission" | "coupons";
type VendorTab = "overview" | "products" | "orders" | "analytics";
type PaymentMethod = "upi" | "card" | "netbanking" | "cod";

const statusColor = (s: string) =>
  ({ delivered: "bg-emerald-100 text-emerald-700", processing: "bg-amber-100 text-amber-700", shipped: "bg-blue-100 text-blue-700", cancelled: "bg-red-100 text-red-700" }[s] ?? "bg-gray-100 text-gray-600");
const statusLabel = (s: string) =>
  ({ delivered: "Delivered", processing: "Processing", shipped: "Shipped", cancelled: "Cancelled" }[s] ?? s);
const vendorStatusColor = (s: string) =>
  ({ active: "bg-emerald-100 text-emerald-700", pending: "bg-amber-100 text-amber-700", suspended: "bg-red-100 text-red-700" }[s] ?? "bg-gray-100 text-gray-600");

function Stars({ rating, size = 12 }: { rating: number; size?: number }) {
  return (
    <div className="flex">
      {Array.from({ length: 5 }).map((_, i) => (
        <Star key={i} size={size} className={i < Math.floor(rating) ? "text-[#C8965A] fill-[#C8965A]" : "text-gray-200 fill-gray-200"} />
      ))}
    </div>
  );
}

function formatINR(amount: number) { return "₹" + (amount * 84).toLocaleString("en-IN"); }

const PRODUCTS_PER_PAGE = 12;
const MAX_PRICE = 250;

// ─── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const productsRef = useRef<HTMLDivElement>(null);
  const accountDropRef = useRef<HTMLDivElement>(null);

  // Auth
  const [isLoggedIn, setIsLoggedIn] = useState(true);
  const [currentUser, setCurrentUser] = useState<UserProfile>({ firstName: "Alex", email: "alex@example.com", role: "admin", points: 2450 });

  // Nav
  const [page, setPage] = useState<Page>("shop");
  const [menuOpen, setMenuOpen] = useState(false);
  const [accountDropOpen, setAccountDropOpen] = useState(false);

  // Cart
  const [cart, setCart] = useState<CartItem[]>([]);
  const [cartOpen, setCartOpen] = useState(false);

  // Shop / Filters
  const [search, setSearch] = useState("");
  const [catFilter, setCatFilter] = useState("All");
  const [wishlist, setWishlist] = useState<number[]>([2, 5, 13]);
  const [qty, setQty] = useState(1);
  const [currentProductPage, setCurrentProductPage] = useState(1);
  const [filterOpen, setFilterOpen] = useState(false);
  const [priceRange, setPriceRange] = useState<[number, number]>([0, MAX_PRICE]);
  const [filterCategories, setFilterCategories] = useState<string[]>([]);
  const [sortBy, setSortBy] = useState("newest");
  const [inStockOnly, setInStockOnly] = useState(false);
  const [filterTags, setFilterTags] = useState<string[]>([]);
  const [selProduct, setSelProduct] = useState<Product>(ALL_PRODUCTS[0]);
  const [recentlyViewed, setRecentlyViewed] = useState<Product[]>([ALL_PRODUCTS[1], ALL_PRODUCTS[0]]);
  const [isMobile, setIsMobile] = useState(false);

  // Search overlay
  const [searchOpen, setSearchOpen] = useState(false);
  const [globalSearch, setGlobalSearch] = useState("");

  // Account
  const [accTab, setAccTab] = useState<AccTab>("overview");
  const [orders, setOrders] = useState<Order[]>(ORDERS_INIT);
  const [selOrder, setSelOrder] = useState<Order>(ORDERS_INIT[0]);
  const [loginTab, setLoginTab] = useState<"login" | "register">("login");
  const [savedAddresses, setSavedAddresses] = useState<SavedAddress[]>([
    { id: 1, label: "Home", name: "Alex Johnson", street: "42 Maple Street", city: "Portland", state: "OR", pincode: "97201", phone: "+1 503 555 0142", isDefault: true },
    { id: 2, label: "Work", name: "Alex Johnson", street: "1 Main St, Suite 400", city: "Portland", state: "OR", pincode: "97204", phone: "+1 503 555 9876", isDefault: false },
  ]);
  const [savedPayments, setSavedPayments] = useState<SavedPayment[]>([
    { id: 1, type: "card", label: "Visa •••• 4242 (exp 09/27)", isDefault: true },
    { id: 2, type: "upi", label: "user@paytm", isDefault: false },
  ]);
  const [loyaltyTx] = useState([
    { date: "Jul 10, 2025", desc: "Order ORD-2025-1001", pts: +1830, type: "earn" },
    { date: "Jun 28, 2025", desc: "Order ORD-2025-0892", pts: +2340, type: "earn" },
    { date: "Jun 20, 2025", desc: "Redeemed at checkout", pts: -500, type: "redeem" },
    { date: "May 14, 2025", desc: "Order ORD-2025-0751", pts: +780, type: "earn" },
  ]);

  // Cancellation
  const [cancelOrderOpen, setCancelOrderOpen] = useState(false);
  const [cancellingOrder, setCancellingOrder] = useState<Order | null>(null);
  const [cancelReason, setCancelReason] = useState("");
  const [cancelDone, setCancelDone] = useState(false);

  // Admin
  const [adminTab, setAdminTab] = useState<AdminTab>("overview");
  const [vendorStatuses, setVendorStatuses] = useState<Record<number, string>>(Object.fromEntries(VENDORS.map(v => [v.id, v.status])));
  const [commissionRate, setCommissionRate] = useState(15);
  const [coupons, setCoupons] = useState<Coupon[]>(COUPONS_INIT);
  const [newCoupon, setNewCoupon] = useState({ code: "", discount: "", type: "percent", scope: "all", expires: "" });

  // Vendor
  const [vendorTab, setVendorTab] = useState<VendorTab>("overview");
  const [vendorProductsList, setVendorProductsList] = useState<Product[]>(ALL_PRODUCTS);
  const [vendorOrderStatuses, setVendorOrderStatuses] = useState<Record<string, string>>(Object.fromEntries(ORDERS_INIT.map(o => [o.id, o.status])));
  const [manageOrderOpen, setManageOrderOpen] = useState(false);
  const [managingOrder, setManagingOrder] = useState<Order | null>(null);
  const [managingStatus, setManagingStatus] = useState("");
  const [addProductOpen, setAddProductOpen] = useState(false);
  const [newProduct, setNewProduct] = useState({ name: "", category: "Home", price: "", originalPrice: "", stock: "", description: "", badge: "", image: "" });
  const [csvUploadOpen, setCsvUploadOpen] = useState(false);
  const [csvPreview, setCsvPreview] = useState<Partial<Product>[]>([]);

  // Payment
  const [paymentItems, setPaymentItems] = useState<CartItem[]>([]);
  const [paymentMethod, setPaymentMethod] = useState<PaymentMethod>("upi");
  const [upiId, setUpiId] = useState("user@paytm");
  const [cardNum, setCardNum] = useState("");
  const [cardName, setCardName] = useState("");
  const [cardExpiry, setCardExpiry] = useState("");
  const [cardCvv, setCardCvv] = useState("");
  const [selectedBank, setSelectedBank] = useState("SBI");
  const [deliveryAddress, setDeliveryAddress] = useState({ name: "Alex Johnson", phone: "+91 98765 43210", street: "42 Maple Street", city: "Portland", state: "OR", pincode: "97201" });
  const [confirmedOrderId, setConfirmedOrderId] = useState("");
  const [redeemPoints, setRedeemPoints] = useState(false);

  // ─── Effects ───────────────────────────────────────────────────────────────

  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (accountDropRef.current && !accountDropRef.current.contains(e.target as Node)) {
        setAccountDropOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => { setCurrentProductPage(1); }, [search, catFilter, priceRange, filterCategories, sortBy, inStockOnly, filterTags]);

  // ─── Computed ──────────────────────────────────────────────────────────────

  const filteredProducts = (() => {
    let res = ALL_PRODUCTS.filter(p => {
      const q = search.toLowerCase();
      const matchSearch = !search || p.name.toLowerCase().includes(q) || p.category.toLowerCase().includes(q);
      const matchChip = catFilter === "All" || p.category === catFilter;
      const matchCat = filterCategories.length === 0 || filterCategories.includes(p.category);
      const matchPrice = p.price >= priceRange[0] && p.price <= priceRange[1];
      const matchStock = !inStockOnly || p.stock > 0;
      const matchTag = filterTags.length === 0 || (p.badge && filterTags.includes(p.badge));
      return matchSearch && matchChip && matchCat && matchPrice && matchStock && matchTag;
    });
    if (sortBy === "price-low") res = [...res].sort((a, b) => a.price - b.price);
    else if (sortBy === "price-high") res = [...res].sort((a, b) => b.price - a.price);
    else if (sortBy === "bestsellers") res = [...res].sort((a, b) => b.reviews - a.reviews);
    return res;
  })();

  const totalPages = Math.ceil(filteredProducts.length / PRODUCTS_PER_PAGE);
  const pagedProducts = filteredProducts.slice((currentProductPage - 1) * PRODUCTS_PER_PAGE, currentProductPage * PRODUCTS_PER_PAGE);

  const activeFilterCount = [
    priceRange[0] > 0 || priceRange[1] < MAX_PRICE,
    filterCategories.length > 0,
    sortBy !== "newest",
    inStockOnly,
    filterTags.length > 0,
  ].filter(Boolean).length;

  const cartTotal = cart.reduce((s, c) => s + c.product.price * c.qty, 0);
  const cartCount = cart.reduce((s, c) => s + c.qty, 0);

  const payTotal = paymentItems.reduce((s, c) => s + c.product.price * c.qty, 0);
  const payShipping = payTotal > 150 ? 0 : 12;
  const payTax = Math.round(payTotal * 0.08);
  const pointsDiscount = redeemPoints ? Math.min(Math.floor(currentUser.points / 100), Math.floor(payTotal * 0.2)) : 0;
  const payGrand = payTotal + payShipping + payTax - pointsDiscount;

  const analyticsData = [...vendorProductsList].map(p => ({
    ...p,
    totalOrders: PRODUCT_ORDER_COUNTS[p.id] ?? 50,
    revenue: p.price * (PRODUCT_ORDER_COUNTS[p.id] ?? 50),
    profit: Math.round(p.price * (PRODUCT_ORDER_COUNTS[p.id] ?? 50) * 0.35),
    stockStatus: p.stock > 15 ? "in-stock" : p.stock > 0 ? "low-stock" : "out-of-stock",
  })).sort((a, b) => b.profit - a.profit);

  const searchResults = globalSearch.length > 1
    ? ALL_PRODUCTS.filter(p => p.name.toLowerCase().includes(globalSearch.toLowerCase()) || p.category.toLowerCase().includes(globalSearch.toLowerCase()))
    : [];

  // ─── Handlers ──────────────────────────────────────────────────────────────

  const goPage = (p: Page) => { setPage(p); setMenuOpen(false); setAccountDropOpen(false); window.scrollTo(0, 0); };
  const addToCart = (product: Product, q = 1) => {
    setCart(prev => { const ex = prev.find(c => c.product.id === product.id); if (ex) return prev.map(c => c.product.id === product.id ? { ...c, qty: c.qty + q } : c); return [...prev, { product, qty: q }]; });
  };
  const removeFromCart = (id: number) => setCart(prev => prev.filter(c => c.product.id !== id));
  const updateQty = (id: number, q: number) => { if (q < 1) { removeFromCart(id); return; } setCart(prev => prev.map(c => c.product.id === id ? { ...c, qty: q } : c)); };
  const toggleWishlist = (id: number) => setWishlist(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  const openProduct = (p: Product) => { setSelProduct(p); setQty(1); setRecentlyViewed(prev => [p, ...prev.filter(x => x.id !== p.id)].slice(0, 8)); goPage("product"); };
  const reorder = (o: Order) => { o.items.forEach(item => { const p = ALL_PRODUCTS.find(x => x.name === item.name); if (p) addToCart(p, item.qty); }); setCartOpen(true); };
  const buyNow = () => { setPaymentItems([{ product: selProduct, qty }]); goPage("payment"); };
  const checkoutCart = () => { setPaymentItems([...cart]); setCartOpen(false); goPage("payment"); };
  const placeOrder = () => {
    const orderId = "ORD-" + Date.now().toString().slice(-8);
    const trackNum = "1Z999AA" + Math.floor(Math.random() * 1e10).toString().padStart(10, "0");
    const total = paymentItems.reduce((s, c) => s + c.product.price * c.qty, 0);
    const newOrder: Order = { id: orderId, date: new Date().toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" }), status: "processing", total, items: paymentItems.map(c => ({ name: c.product.name, qty: c.qty, price: c.product.price, image: c.product.image })), address: `${deliveryAddress.street}, ${deliveryAddress.city} ${deliveryAddress.state}`, tracking: trackNum };
    setOrders(prev => [newOrder, ...prev]);
    setConfirmedOrderId(orderId);
    if (redeemPoints) setCurrentUser(u => ({ ...u, points: Math.max(0, u.points - pointsDiscount * 100) }));
    setCurrentUser(u => ({ ...u, points: u.points + Math.round(total * 10) }));
    setCart([]);
    goPage("confirmed");
  };
  const signOut = () => { setIsLoggedIn(false); setAccountDropOpen(false); goPage("shop"); };
  const signIn = () => { setIsLoggedIn(true); goPage("hub"); };
  const openCancel = (o: Order) => { setCancellingOrder(o); setCancelReason(""); setCancelDone(false); setCancelOrderOpen(true); };
  const confirmCancel = () => {
    if (!cancellingOrder || !cancelReason) return;
    setOrders(prev => prev.map(o => o.id === cancellingOrder.id ? { ...o, status: "cancelled" as const } : o));
    setCancelDone(true);
  };
  const approveVendor = (id: number) => setVendorStatuses(prev => ({ ...prev, [id]: "active" }));
  const suspendVendor = (id: number) => setVendorStatuses(prev => ({ ...prev, [id]: "suspended" }));
  const openManageOrder = (o: Order) => { setManagingOrder(o); setManagingStatus(vendorOrderStatuses[o.id] ?? o.status); setManageOrderOpen(true); };
  const saveManageOrder = () => { if (!managingOrder) return; setVendorOrderStatuses(prev => ({ ...prev, [managingOrder.id]: managingStatus })); setManageOrderOpen(false); };
  const submitAddProduct = () => {
    if (!newProduct.name || !newProduct.price) return;
    setVendorProductsList(prev => [...prev, { id: Date.now(), name: newProduct.name, category: newProduct.category, price: parseFloat(newProduct.price) || 0, originalPrice: newProduct.originalPrice ? parseFloat(newProduct.originalPrice) : undefined, stock: parseInt(newProduct.stock) || 0, description: newProduct.description, badge: newProduct.badge || undefined, image: newProduct.image || "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=600&h=600&fit=crop&auto=format", rating: 0, reviews: 0, vendor: "Artisan Goods Co." }]);
    setNewProduct({ name: "", category: "Home", price: "", originalPrice: "", stock: "", description: "", badge: "", image: "" });
    setAddProductOpen(false);
  };
  const handleCSVFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const lines = (ev.target?.result as string).split("\n").filter(Boolean).slice(1);
      const parsed = lines.map(line => { const [name, category, price, stock, description] = line.split(","); return { name: name?.trim(), category: category?.trim() || "Home", price: parseFloat(price || "0"), stock: parseInt(stock || "0"), description: description?.trim() || "" }; }).filter(p => p.name && p.price > 0);
      setCsvPreview(parsed);
    };
    reader.readAsText(file);
  };
  const importCSV = () => {
    const newProducts: Product[] = csvPreview.map((p, i) => ({ id: Date.now() + i, name: p.name!, category: p.category || "Home", price: p.price!, stock: p.stock || 0, description: p.description || "", image: "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=600&h=600&fit=crop&auto=format", rating: 0, reviews: 0, vendor: "Artisan Goods Co." }));
    setVendorProductsList(prev => [...prev, ...newProducts]);
    setCsvPreview([]);
    setCsvUploadOpen(false);
  };
  const addCoupon = () => {
    if (!newCoupon.code || !newCoupon.discount) return;
    setCoupons(prev => [...prev, { id: Date.now(), code: newCoupon.code.toUpperCase(), discount: parseFloat(newCoupon.discount), type: newCoupon.type as "percent" | "flat", scope: newCoupon.scope, expires: newCoupon.expires || "2025-12-31", uses: 0, active: true }]);
    setNewCoupon({ code: "", discount: "", type: "percent", scope: "all", expires: "" });
  };
  const toggleCoupon = (id: number) => setCoupons(prev => prev.map(c => c.id === id ? { ...c, active: !c.active } : c));
  const clearFilters = () => { setPriceRange([0, MAX_PRICE]); setFilterCategories([]); setSortBy("newest"); setInStockOnly(false); setFilterTags([]); };

  // ─── Cancel Order Modal ────────────────────────────────────────────────────

  const CancelModal = () => {
    if (!cancellingOrder) return null;
    const isShipped = cancellingOrder.status === "shipped";
    const refundAmt = isShipped ? Math.round(cancellingOrder.total * 0.85) : cancellingOrder.total;
    const refundPct = isShipped ? 85 : 100;
    const reasons = ["Changed my mind", "Ordered by mistake", "Found a better price", "Item damaged / not as described", "Wrong item ordered", "Delivery taking too long", "Other"];
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setCancelOrderOpen(false)} />
        <div className="relative bg-white rounded-3xl w-full max-w-md shadow-2xl overflow-hidden">
          <div className="bg-gradient-to-r from-red-600 to-red-500 px-6 py-5 flex items-center justify-between">
            <div><h3 className="text-white font-serif font-bold text-xl">Cancel Order</h3><p className="text-white/70 text-sm mt-0.5">{cancellingOrder.id}</p></div>
            <button onClick={() => setCancelOrderOpen(false)} className="text-white/60 hover:text-white"><X size={20} /></button>
          </div>
          <div className="p-6">
            {cancelDone ? (
              <div className="text-center py-4">
                <CheckCircle size={48} className="text-emerald-500 mx-auto mb-4" />
                <h4 className="font-serif font-bold text-xl text-[#1B2B4B] mb-2">Order Cancelled</h4>
                <p className="text-[#6B6560] text-sm mb-2">Your cancellation has been processed.</p>
                <div className="bg-emerald-50 rounded-2xl p-4 mb-4">
                  <p className="text-emerald-800 font-medium">Refund of <strong>${refundAmt}</strong> will be credited in 5–7 business days.</p>
                  <p className="text-emerald-700 text-xs mt-1">≈ {formatINR(refundAmt)}</p>
                </div>
                <button onClick={() => setCancelOrderOpen(false)} className="w-full bg-[#1B2B4B] text-white py-3 rounded-xl font-medium hover:bg-[#C8965A] transition">Done</button>
              </div>
            ) : (
              <>
                <div className="bg-amber-50 border border-amber-100 rounded-2xl p-4 mb-5">
                  <div className="flex items-start gap-3">
                    <AlertTriangle size={18} className="text-amber-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-amber-800 font-medium text-sm">Refund Policy</p>
                      <p className="text-amber-700 text-xs mt-1">{isShipped ? "This order is already shipped. You'll receive an 85% refund. The 15% covers return shipping and processing." : "Full 100% refund will be issued as the order hasn't shipped yet."}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-amber-900 font-bold text-lg">{refundPct}% refund</span>
                        <span className="text-amber-700 text-sm">= ${refundAmt} ({formatINR(refundAmt)})</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="mb-4">
                  <label className="text-sm font-medium text-[#1A1410] block mb-3">Why are you cancelling?</label>
                  <div className="space-y-2">
                    {reasons.map(r => (
                      <label key={r} className={`flex items-center gap-3 p-3 rounded-xl cursor-pointer border transition ${cancelReason === r ? "border-[#1B2B4B] bg-[#1B2B4B]/5" : "border-gray-100 hover:border-gray-200"}`}>
                        <input type="radio" name="reason" value={r} checked={cancelReason === r} onChange={() => setCancelReason(r)} className="accent-[#1B2B4B]" />
                        <span className="text-sm text-[#1A1410]">{r}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <div className="flex gap-3">
                  <button onClick={() => setCancelOrderOpen(false)} className="flex-1 border border-gray-200 rounded-xl py-3 text-sm font-medium hover:bg-gray-50 transition">Keep Order</button>
                  <button onClick={confirmCancel} disabled={!cancelReason} className="flex-1 bg-red-500 text-white rounded-xl py-3 text-sm font-medium hover:bg-red-600 transition disabled:opacity-40">Cancel Order</button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    );
  };

  // ─── Search Overlay ────────────────────────────────────────────────────────

  const SearchOverlay = () => (
    <div className="fixed inset-0 z-50 flex flex-col">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => { setSearchOpen(false); setGlobalSearch(""); }} />
      <div className="relative bg-white shadow-2xl">
        <div className="max-w-3xl mx-auto flex items-center gap-3 p-4">
          <Search size={20} className="text-[#C8965A] flex-shrink-0" />
          <input autoFocus value={globalSearch} onChange={e => setGlobalSearch(e.target.value)} placeholder="Search products, categories..."
            className="flex-1 text-lg outline-none bg-transparent text-[#1A1410] placeholder-gray-400" />
          <button onClick={() => { setSearchOpen(false); setGlobalSearch(""); }} className="text-gray-400 hover:text-gray-600"><X size={20} /></button>
        </div>
        {globalSearch.length > 1 && (
          <div className="max-w-3xl mx-auto px-4 pb-4 border-t border-gray-100">
            {searchResults.length === 0 ? <p className="text-center text-gray-400 py-8">No products found for &quot;{globalSearch}&quot;</p> : (
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-4 max-h-[60vh] overflow-y-auto">
                {searchResults.map(p => (
                  <button key={p.id} onClick={() => { setSearchOpen(false); setGlobalSearch(""); openProduct(p); }} className="flex items-center gap-3 p-2 rounded-xl hover:bg-gray-50 text-left transition">
                    <img src={p.image} alt={p.name} className="w-14 h-14 rounded-lg object-cover flex-shrink-0" />
                    <div className="min-w-0"><p className="text-sm font-medium text-[#1A1410] truncate">{p.name}</p><p className="text-xs text-[#6B6560]">{p.category}</p><p className="text-sm font-bold text-[#C8965A]">${p.price}</p></div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        {globalSearch.length === 0 && (
          <div className="max-w-3xl mx-auto px-4 pb-4 border-t border-gray-100">
            <p className="text-xs text-gray-400 uppercase tracking-widest pt-4 pb-2 font-medium">Popular searches</p>
            <div className="flex flex-wrap gap-2">{["Leather Bag", "Ceramic", "Wool", "Cast Iron", "Linen", "Wallet", "Compass", "Copper"].map(t => <button key={t} onClick={() => setGlobalSearch(t)} className="px-3 py-1.5 bg-gray-100 rounded-full text-sm text-[#1A1410] hover:bg-[#EDE8E0] transition">{t}</button>)}</div>
          </div>
        )}
      </div>
    </div>
  );

  // ─── Filter Panel ──────────────────────────────────────────────────────────

  const allCategories = ["Bags", "Home", "Apparel", "Accessories", "Kitchen"];
  const FilterContent = () => (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 flex-shrink-0">
        <div className="flex items-center gap-2"><SlidersHorizontal size={18} className="text-[#C8965A]" /><h3 className="font-serif font-bold text-lg text-[#1B2B4B]">Filters</h3>{activeFilterCount > 0 && <span className="bg-[#C8965A] text-white text-xs rounded-full px-2 py-0.5">{activeFilterCount}</span>}</div>
        <button onClick={() => setFilterOpen(false)} className="text-gray-400 hover:text-gray-600"><X size={18} /></button>
      </div>
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
        {/* Price Range */}
        <div>
          <h4 className="font-medium text-sm text-[#1A1410] mb-3">Price Range</h4>
          <div className="flex justify-between text-sm font-medium text-[#1B2B4B] mb-3">
            <span>${priceRange[0]}</span><span>${priceRange[1]}</span>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-[#6B6560]"><span>Min</span>
              <input type="range" min={0} max={MAX_PRICE} step={5} value={priceRange[0]}
                onChange={e => setPriceRange([Math.min(+e.target.value, priceRange[1] - 10), priceRange[1]])}
                className="flex-1 accent-[#1B2B4B] cursor-pointer" />
            </div>
            <div className="flex items-center gap-2 text-xs text-[#6B6560]"><span>Max</span>
              <input type="range" min={0} max={MAX_PRICE} step={5} value={priceRange[1]}
                onChange={e => setPriceRange([priceRange[0], Math.max(+e.target.value, priceRange[0] + 10)])}
                className="flex-1 accent-[#1B2B4B] cursor-pointer" />
            </div>
          </div>
          <div className="flex justify-between text-xs text-[#6B6560] mt-1"><span>≈ {formatINR(priceRange[0])}</span><span>≈ {formatINR(priceRange[1])}</span></div>
        </div>
        {/* Category */}
        <div>
          <h4 className="font-medium text-sm text-[#1A1410] mb-3">Category</h4>
          <div className="space-y-2">
            {allCategories.map(c => (
              <label key={c} className="flex items-center gap-3 cursor-pointer group">
                <div className={`w-4 h-4 rounded border-2 flex items-center justify-center transition ${filterCategories.includes(c) ? "bg-[#1B2B4B] border-[#1B2B4B]" : "border-gray-300 group-hover:border-[#1B2B4B]"}`}
                  onClick={() => setFilterCategories(prev => prev.includes(c) ? prev.filter(x => x !== c) : [...prev, c])}>
                  {filterCategories.includes(c) && <Check size={10} className="text-white" />}
                </div>
                <span className="text-sm text-[#1A1410]">{c}</span>
              </label>
            ))}
          </div>
        </div>
        {/* Sort By */}
        <div>
          <h4 className="font-medium text-sm text-[#1A1410] mb-3">Sort By</h4>
          <div className="space-y-2">
            {[["newest", "Newest"], ["price-low", "Price: Low to High"], ["price-high", "Price: High to Low"], ["bestsellers", "Bestsellers"]].map(([val, label]) => (
              <label key={val} className="flex items-center gap-3 cursor-pointer group">
                <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center transition ${sortBy === val ? "border-[#1B2B4B]" : "border-gray-300"}`} onClick={() => setSortBy(val)}>
                  {sortBy === val && <div className="w-2 h-2 rounded-full bg-[#1B2B4B]" />}
                </div>
                <span className="text-sm text-[#1A1410]">{label}</span>
              </label>
            ))}
          </div>
        </div>
        {/* Availability */}
        <div>
          <h4 className="font-medium text-sm text-[#1A1410] mb-3">Availability</h4>
          <label className="flex items-center gap-3 cursor-pointer">
            <div className={`w-4 h-4 rounded border-2 flex items-center justify-center transition ${inStockOnly ? "bg-[#1B2B4B] border-[#1B2B4B]" : "border-gray-300"}`} onClick={() => setInStockOnly(v => !v)}>
              {inStockOnly && <Check size={10} className="text-white" />}
            </div>
            <span className="text-sm text-[#1A1410]">In Stock only</span>
          </label>
        </div>
        {/* Tags */}
        <div>
          <h4 className="font-medium text-sm text-[#1A1410] mb-3">Tags</h4>
          <div className="space-y-2">
            {["Sale", "New", "Bestseller"].map(t => (
              <label key={t} className="flex items-center gap-3 cursor-pointer group">
                <div className={`w-4 h-4 rounded border-2 flex items-center justify-center transition ${filterTags.includes(t) ? "bg-[#1B2B4B] border-[#1B2B4B]" : "border-gray-300 group-hover:border-[#1B2B4B]"}`} onClick={() => setFilterTags(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])}>
                  {filterTags.includes(t) && <Check size={10} className="text-white" />}
                </div>
                <span className="text-sm text-[#1A1410]">{t}</span>
              </label>
            ))}
          </div>
        </div>
      </div>
      <div className="px-6 py-4 border-t border-gray-100 flex gap-3 flex-shrink-0">
        <button onClick={clearFilters} className="flex-1 border border-gray-200 rounded-xl py-2.5 text-sm font-medium hover:bg-gray-50 transition">Clear All</button>
        <button onClick={() => setFilterOpen(false)} className="flex-1 bg-[#1B2B4B] text-white rounded-xl py-2.5 text-sm font-medium hover:bg-[#C8965A] transition">Apply Filters</button>
      </div>
    </div>
  );

  const FilterPanel = () => (
    <>
      {filterOpen && <div className="fixed inset-0 bg-black/40 z-40" onClick={() => setFilterOpen(false)} />}
      {/* Desktop sidebar */}
      <div className={`hidden md:flex fixed inset-y-0 left-0 z-50 w-80 bg-white shadow-2xl flex-col transition-transform duration-300 ${filterOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <FilterContent />
      </div>
      {/* Mobile bottom sheet */}
      <div className={`md:hidden fixed inset-x-0 bottom-0 z-50 bg-white rounded-t-3xl shadow-2xl flex flex-col transition-transform duration-300 ${filterOpen ? "translate-y-0" : "translate-y-full"}`} style={{ maxHeight: "85vh" }}>
        <div className="w-12 h-1.5 bg-gray-200 rounded-full mx-auto mt-3 mb-1 flex-shrink-0" />
        <FilterContent />
      </div>
    </>
  );

  // ─── Manage Order Modal ────────────────────────────────────────────────────

  const ManageOrderModal = () => {
    if (!managingOrder) return null;
    const cs = vendorOrderStatuses[managingOrder.id] ?? managingOrder.status;
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="absolute inset-0 bg-black/50" onClick={() => setManageOrderOpen(false)} />
        <div className="relative bg-white rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden">
          <div className="bg-[#1B2B4B] px-6 py-4 flex items-center justify-between">
            <div><h3 className="text-white font-serif font-bold text-lg">Manage Order</h3><p className="text-white/60 text-sm">{managingOrder.id}</p></div>
            <button onClick={() => setManageOrderOpen(false)} className="text-white/60 hover:text-white"><X size={20} /></button>
          </div>
          <div className="p-6">
            <div className="space-y-3 mb-5">{managingOrder.items.map((item, i) => <div key={i} className="flex items-center gap-3"><img src={item.image} alt={item.name} className="w-12 h-12 rounded-lg object-cover" /><div className="flex-1 min-w-0"><p className="font-medium text-sm truncate">{item.name}</p><p className="text-[#6B6560] text-xs">Qty: {item.qty} · ${item.price}</p></div></div>)}</div>
            <div className="mb-4"><label className="text-sm font-medium block mb-2">Update Status</label><select value={managingStatus} onChange={e => setManagingStatus(e.target.value)} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white"><option value="processing">Processing</option><option value="shipped">Shipped</option><option value="delivered">Delivered</option><option value="cancelled">Cancelled</option></select></div>
            {(cs === "shipped" || managingStatus === "shipped") && managingStatus !== "cancelled" && (
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-4">
                <div className="flex items-center gap-2 mb-2"><AlertTriangle size={16} className="text-amber-600" /><p className="text-amber-800 font-medium text-sm">Cancel Shipping</p></div>
                <p className="text-amber-700 text-xs mb-3">This order has been shipped. Cancelling will initiate a return process.</p>
                <button onClick={() => setManagingStatus("cancelled")} className="w-full bg-red-500 text-white rounded-lg py-2 text-sm font-medium hover:bg-red-600 transition">Cancel Shipping &amp; Initiate Return</button>
              </div>
            )}
            <div className="bg-gray-50 rounded-xl p-4 mb-4"><p className="text-xs text-gray-500 mb-1">Delivery Address</p><p className="text-sm">{managingOrder.address}</p>{managingOrder.tracking && <p className="text-xs text-[#6B6560] mt-1">Tracking: {managingOrder.tracking}</p>}</div>
            <div className="flex gap-3"><button onClick={() => setManageOrderOpen(false)} className="flex-1 border border-gray-200 rounded-xl py-2.5 text-sm font-medium hover:bg-gray-50 transition">Cancel</button><button onClick={saveManageOrder} className="flex-1 bg-[#1B2B4B] text-white rounded-xl py-2.5 text-sm font-medium hover:bg-[#C8965A] transition">Save Changes</button></div>
          </div>
        </div>
      </div>
    );
  };

  // ─── Add Product Modal ─────────────────────────────────────────────────────

  const AddProductModal = () => (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={() => setAddProductOpen(false)} />
      <div className="relative bg-white rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div className="bg-[#1B2B4B] px-6 py-4 flex items-center justify-between flex-shrink-0"><h3 className="text-white font-serif font-bold text-lg">Add New Product</h3><button onClick={() => setAddProductOpen(false)} className="text-white/60 hover:text-white"><X size={20} /></button></div>
        <div className="p-6 overflow-y-auto flex-1 space-y-4">
          <div><label className="text-sm font-medium block mb-1.5">Product Name *</label><input value={newProduct.name} onChange={e => setNewProduct(p => ({ ...p, name: e.target.value }))} placeholder="e.g. Hand-stitched Leather Journal" className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B]" /></div>
          <div className="grid grid-cols-2 gap-4">
            <div><label className="text-sm font-medium block mb-1.5">Category</label><select value={newProduct.category} onChange={e => setNewProduct(p => ({ ...p, category: e.target.value }))} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white">{["Bags", "Home", "Apparel", "Accessories", "Kitchen"].map(c => <option key={c}>{c}</option>)}</select></div>
            <div><label className="text-sm font-medium block mb-1.5">Badge</label><select value={newProduct.badge} onChange={e => setNewProduct(p => ({ ...p, badge: e.target.value }))} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white"><option value="">None</option>{["New", "Sale", "Bestseller"].map(b => <option key={b}>{b}</option>)}</select></div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div><label className="text-sm font-medium block mb-1.5">Price ($) *</label><input type="number" value={newProduct.price} onChange={e => setNewProduct(p => ({ ...p, price: e.target.value }))} placeholder="0.00" className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B]" /></div>
            <div><label className="text-sm font-medium block mb-1.5">Original Price ($)</label><input type="number" value={newProduct.originalPrice} onChange={e => setNewProduct(p => ({ ...p, originalPrice: e.target.value }))} placeholder="Optional" className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B]" /></div>
          </div>
          <div><label className="text-sm font-medium block mb-1.5">Stock Quantity</label><input type="number" value={newProduct.stock} onChange={e => setNewProduct(p => ({ ...p, stock: e.target.value }))} placeholder="0" className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B]" /></div>
          <div><label className="text-sm font-medium block mb-1.5">Description</label><textarea value={newProduct.description} onChange={e => setNewProduct(p => ({ ...p, description: e.target.value }))} rows={3} placeholder="Describe your product..." className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B] resize-none" /></div>
          <div><label className="text-sm font-medium block mb-1.5">Image URL</label><input value={newProduct.image} onChange={e => setNewProduct(p => ({ ...p, image: e.target.value }))} placeholder="https://..." className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B]" /></div>
        </div>
        <div className="p-6 border-t border-gray-100 flex gap-3 flex-shrink-0"><button onClick={() => setAddProductOpen(false)} className="flex-1 border border-gray-200 rounded-xl py-2.5 text-sm font-medium hover:bg-gray-50 transition">Cancel</button><button onClick={submitAddProduct} className="flex-1 bg-[#1B2B4B] text-white rounded-xl py-2.5 text-sm font-medium hover:bg-[#C8965A] transition">Add Product</button></div>
      </div>
    </div>
  );

  // ─── CSV Upload Modal ──────────────────────────────────────────────────────

  const CSVModal = () => (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={() => { setCsvUploadOpen(false); setCsvPreview([]); }} />
      <div className="relative bg-white rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
        <div className="bg-[#1B2B4B] px-6 py-4 flex items-center justify-between flex-shrink-0"><div><h3 className="text-white font-serif font-bold text-lg">Bulk Product Upload</h3><p className="text-white/60 text-xs mt-0.5">CSV format: name, category, price, stock, description</p></div><button onClick={() => { setCsvUploadOpen(false); setCsvPreview([]); }} className="text-white/60 hover:text-white"><X size={20} /></button></div>
        <div className="p-6 overflow-y-auto flex-1">
          {csvPreview.length === 0 ? (
            <label className="flex flex-col items-center justify-center border-2 border-dashed border-gray-200 rounded-2xl p-12 cursor-pointer hover:border-[#C8965A] transition group">
              <Upload size={36} className="text-gray-300 group-hover:text-[#C8965A] mb-3 transition" />
              <p className="font-medium text-[#1A1410] mb-1">Click to upload CSV</p>
              <p className="text-xs text-[#6B6560]">Supports CSV files with columns: name, category, price, stock, description</p>
              <input type="file" accept=".csv" className="hidden" onChange={handleCSVFile} />
            </label>
          ) : (
            <div>
              <div className="flex items-center gap-2 mb-4"><CheckCircle size={18} className="text-emerald-600" /><p className="text-sm font-medium text-emerald-700">{csvPreview.length} products ready to import</p></div>
              <div className="overflow-x-auto rounded-xl border border-gray-100">
                <table className="w-full text-sm"><thead><tr className="bg-gray-50">{["Name", "Category", "Price", "Stock"].map(h => <th key={h} className="text-left py-3 px-4 text-xs text-[#6B6560] uppercase font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-gray-50">{csvPreview.slice(0, 10).map((p, i) => <tr key={i}><td className="py-3 px-4 font-medium">{p.name}</td><td className="py-3 px-4 text-[#6B6560]">{p.category}</td><td className="py-3 px-4">${p.price}</td><td className="py-3 px-4">{p.stock}</td></tr>)}</tbody>
                </table>
              </div>
              {csvPreview.length > 10 && <p className="text-xs text-[#6B6560] mt-2 text-center">...and {csvPreview.length - 10} more</p>}
            </div>
          )}
        </div>
        <div className="p-6 border-t border-gray-100 flex gap-3 flex-shrink-0">
          <button onClick={() => { setCsvUploadOpen(false); setCsvPreview([]); }} className="flex-1 border border-gray-200 rounded-xl py-2.5 text-sm font-medium hover:bg-gray-50 transition">Cancel</button>
          {csvPreview.length > 0 && <button onClick={importCSV} className="flex-1 bg-[#1B2B4B] text-white rounded-xl py-2.5 text-sm font-medium hover:bg-[#C8965A] transition">Import {csvPreview.length} Products</button>}
        </div>
      </div>
    </div>
  );

  // ─── Navbar ────────────────────────────────────────────────────────────────

  const Navbar = () => (
    <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-md border-b border-gray-100 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center h-16 gap-4">
        <button onClick={() => goPage("shop")} className="font-serif font-bold text-xl text-[#1B2B4B] tracking-tight flex-shrink-0">Maison</button>
        <nav className="hidden md:flex items-center gap-6 ml-6 flex-1">
          <button onClick={() => goPage("shop")} className="text-sm text-[#6B6560] hover:text-[#1B2B4B] transition font-medium">Shop</button>
          <button onClick={() => goPage("our-story")} className="text-sm text-[#6B6560] hover:text-[#1B2B4B] transition font-medium">Our Story</button>
        </nav>
        <div className="flex items-center gap-1.5 ml-auto">
          <button onClick={() => setSearchOpen(true)} className="w-9 h-9 rounded-full flex items-center justify-center hover:bg-gray-100 transition text-[#6B6560]"><Search size={18} /></button>
          {/* Account dropdown */}
          <div ref={accountDropRef} className="relative">
            <button onClick={() => setAccountDropOpen(v => !v)} className="flex items-center gap-1.5 px-3 py-2 rounded-full hover:bg-gray-100 transition text-sm font-medium text-[#1A1410]">
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${isLoggedIn ? "bg-[#1B2B4B] text-white" : "bg-gray-100 text-[#6B6560]"}`}>
                {isLoggedIn ? currentUser.firstName[0] : <User size={14} />}
              </div>
              <span className="hidden sm:block">{isLoggedIn ? `Hi, ${currentUser.firstName}` : "Account"}</span>
              <ChevronDown size={14} className={`transition-transform ${accountDropOpen ? "rotate-180" : ""}`} />
            </button>
            {accountDropOpen && (
              <div className="absolute right-0 top-full mt-2 w-52 bg-white rounded-2xl shadow-xl border border-gray-100 overflow-hidden z-50">
                {isLoggedIn ? (
                  <>
                    <div className="px-4 py-3 border-b border-gray-50">
                      <p className="font-medium text-sm text-[#1A1410]">{currentUser.firstName}</p>
                      <p className="text-xs text-[#6B6560]">{currentUser.email}</p>
                      <div className="flex items-center gap-1 mt-1"><Zap size={11} className="text-[#C8965A]" /><span className="text-xs text-[#C8965A] font-medium">{currentUser.points.toLocaleString()} pts</span></div>
                    </div>
                    <button onClick={() => goPage("account")} className="w-full text-left px-4 py-3 text-sm hover:bg-gray-50 flex items-center gap-2.5 transition"><User size={15} className="text-[#6B6560]" />My Account</button>
                    {(currentUser.role === "vendor" || currentUser.role === "admin") && <button onClick={() => goPage("vendor")} className="w-full text-left px-4 py-3 text-sm hover:bg-gray-50 flex items-center gap-2.5 transition"><Store size={15} className="text-[#6B6560]" />Vendor Portal</button>}
                    {currentUser.role === "admin" && <button onClick={() => goPage("admin")} className="w-full text-left px-4 py-3 text-sm hover:bg-gray-50 flex items-center gap-2.5 transition"><Settings size={15} className="text-[#6B6560]" />Admin Panel</button>}
                    <div className="border-t border-gray-100" />
                    <button onClick={signOut} className="w-full text-left px-4 py-3 text-sm hover:bg-red-50 text-red-500 flex items-center gap-2.5 transition"><LogOut size={15} />Sign Out</button>
                  </>
                ) : (
                  <>
                    <button onClick={() => { setLoginTab("login"); goPage("login"); }} className="w-full text-left px-4 py-3.5 text-sm hover:bg-gray-50 flex items-center gap-2.5 transition font-medium"><User size={15} className="text-[#6B6560]" />Sign In</button>
                    <button onClick={() => { setLoginTab("register"); goPage("login"); }} className="w-full text-left px-4 py-3.5 text-sm hover:bg-gray-50 flex items-center gap-2.5 transition"><Plus size={15} className="text-[#6B6560]" />Create Account</button>
                  </>
                )}
              </div>
            )}
          </div>
          <button onClick={() => setCartOpen(true)} className="relative w-9 h-9 rounded-full flex items-center justify-center hover:bg-gray-100 transition text-[#6B6560]">
            <ShoppingCart size={18} />
            {cartCount > 0 && <span className="absolute -top-0.5 -right-0.5 bg-[#C8965A] text-white text-xs rounded-full w-4 h-4 flex items-center justify-center font-bold">{cartCount}</span>}
          </button>
          <button onClick={() => setMenuOpen(!menuOpen)} className="md:hidden w-9 h-9 rounded-full flex items-center justify-center hover:bg-gray-100 transition text-[#6B6560]">
            {menuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>
      {menuOpen && (
        <div className="md:hidden bg-white border-t border-gray-100 px-4 py-3 space-y-1">
          {[{ label: "Shop", action: () => goPage("shop") }, { label: "Our Story", action: () => goPage("our-story") }, ...(isLoggedIn ? [{ label: "My Account", action: () => goPage("account") }, { label: "Vendor Portal", action: () => goPage("vendor") }, { label: "Admin Panel", action: () => goPage("admin") }, { label: "Sign Out", action: signOut }] : [{ label: "Sign In", action: () => goPage("login") }, { label: "Create Account", action: () => { setLoginTab("register"); goPage("login"); } }])].map(item => (
            <button key={item.label} onClick={item.action} className="w-full text-left px-3 py-2.5 rounded-xl text-sm text-[#1A1410] hover:bg-gray-50 font-medium">{item.label}</button>
          ))}
        </div>
      )}
    </header>
  );

  // ─── Cart Drawer ──────────────────────────────────────────────────────────

  const CartDrawer = () => (
    <>
      {cartOpen && <div className="fixed inset-0 bg-black/40 z-40" onClick={() => setCartOpen(false)} />}
      <div className={`fixed right-0 top-0 h-full w-full sm:w-96 bg-white z-50 shadow-2xl flex flex-col transition-transform duration-300 ${cartOpen ? "translate-x-0" : "translate-x-full"}`}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100"><h2 className="font-serif font-bold text-lg text-[#1B2B4B]">Cart ({cartCount})</h2><button onClick={() => setCartOpen(false)} className="text-gray-400 hover:text-gray-600"><X size={20} /></button></div>
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {cart.length === 0 ? <div className="text-center py-12"><ShoppingBag size={40} className="text-gray-200 mx-auto mb-3" /><p className="text-[#6B6560]">Your cart is empty</p><button onClick={() => setCartOpen(false)} className="mt-4 text-sm text-[#C8965A] hover:underline">Continue shopping</button></div> :
            cart.map(item => (
              <div key={item.product.id} className="flex gap-3">
                <img src={item.product.image} alt={item.product.name} className="w-16 h-16 rounded-xl object-cover flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm text-[#1A1410] truncate">{item.product.name}</p>
                  <p className="text-[#C8965A] font-bold text-sm">${item.product.price}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <button onClick={() => updateQty(item.product.id, item.qty - 1)} className="w-6 h-6 rounded-full border border-gray-200 text-xs flex items-center justify-center hover:bg-gray-50">−</button>
                    <span className="text-sm w-4 text-center">{item.qty}</span>
                    <button onClick={() => updateQty(item.product.id, item.qty + 1)} className="w-6 h-6 rounded-full border border-gray-200 text-xs flex items-center justify-center hover:bg-gray-50">+</button>
                  </div>
                </div>
                <button onClick={() => removeFromCart(item.product.id)} className="text-gray-300 hover:text-red-400 flex-shrink-0"><Trash2 size={16} /></button>
              </div>
            ))}
        </div>
        {cart.length > 0 && <div className="border-t border-gray-100 p-6"><div className="flex justify-between text-sm mb-1"><span className="text-[#6B6560]">Subtotal</span><span className="font-bold text-[#1A1410]">${cartTotal.toFixed(2)}</span></div><div className="flex justify-between text-xs text-[#6B6560] mb-4"><span>Free shipping on orders over $150</span></div><button onClick={checkoutCart} className="w-full bg-[#1B2B4B] text-white rounded-xl py-3 font-medium hover:bg-[#C8965A] transition">Proceed to Checkout</button></div>}
      </div>
    </>
  );

  // ─── Shop Page ─────────────────────────────────────────────────────────────

  const ShopPage = () => {
    const cats = ["All", ...Array.from(new Set(ALL_PRODUCTS.map(p => p.category)))];
    return (
      <div>
        {/* Hero */}
        <section className="relative min-h-[90vh] flex items-center overflow-hidden">
          <div className="absolute inset-0"><img src="https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=1600&h=900&fit=crop&auto=format" alt="Hero" className="w-full h-full object-cover" /><div className="absolute inset-0 bg-gradient-to-r from-[#1B2B4B]/95 via-[#1B2B4B]/70 to-transparent" /></div>
          <div className="relative max-w-7xl mx-auto px-6 sm:px-8 py-24 w-full">
            <div className="max-w-xl">
              <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded-full px-4 py-1.5 mb-6">
                <Zap size={12} className="text-[#C8965A]" /><span className="text-white/80 text-xs tracking-wider font-medium">SUMMER COLLECTION 2025</span>
              </div>
              <h1 className="text-white font-serif font-bold text-5xl sm:text-6xl lg:text-7xl leading-[1.05] mb-6">Made by Hand.<br /><span className="text-[#C8965A]">Built</span> to Last.</h1>
              <p className="text-white/70 text-lg max-w-md mb-10 leading-relaxed">We source directly from the world&apos;s most dedicated independent makers — so every piece you own carries a story.</p>
              <div className="flex flex-wrap gap-4">
                <button onClick={() => productsRef.current?.scrollIntoView({ behavior: "smooth" })} className="bg-[#C8965A] text-white px-8 py-3.5 rounded-full font-medium hover:bg-[#b07c45] transition shadow-lg hover:shadow-xl">Shop Now</button>
                <button onClick={() => goPage("our-story")} className="border-2 border-white/60 text-white px-8 py-3.5 rounded-full font-medium hover:border-white hover:bg-white/10 transition backdrop-blur-sm">Our Story</button>
              </div>
            </div>
          </div>
          <div className="absolute right-8 bottom-8 hidden lg:grid grid-cols-2 gap-3 max-w-xs opacity-80">
            {ALL_PRODUCTS.slice(0, 4).map(p => <div key={p.id} onClick={() => openProduct(p)} className="relative overflow-hidden rounded-xl cursor-pointer group"><img src={p.image} alt={p.name} className="w-full h-24 object-cover group-hover:scale-105 transition duration-300" /><div className="absolute inset-0 bg-black/30 flex items-end p-2"><p className="text-white text-xs font-medium truncate">{p.name}</p></div></div>)}
          </div>
        </section>

        {/* Promise strip */}
        <div className="bg-[#1B2B4B] py-4">
          <div className="max-w-7xl mx-auto px-6 flex flex-wrap items-center justify-center gap-6 sm:gap-10">
            {[{ icon: <Truck size={16} />, text: "Free shipping over $150" }, { icon: <Shield size={16} />, text: "30-day returns" }, { icon: <Award size={16} />, text: "Artisan-made" }, { icon: <Globe size={16} />, text: "Ships worldwide" }].map(item => (
              <div key={item.text} className="flex items-center gap-2 text-white/80 text-sm"><div className="text-[#C8965A]">{item.icon}</div>{item.text}</div>
            ))}
          </div>
        </div>

        {/* Products */}
        <section ref={productsRef} id="products-section" className="max-w-7xl mx-auto px-4 sm:px-6 py-16">
          <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-6">
            <div className="relative flex-1 max-w-sm">
              <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search products..." className="w-full pl-10 pr-4 py-2.5 border border-gray-200 rounded-xl text-sm outline-none focus:border-[#1B2B4B] bg-white" />
            </div>
            <button onClick={() => setFilterOpen(true)} className="flex items-center gap-2 px-4 py-2.5 border border-gray-200 rounded-xl text-sm font-medium hover:border-[#1B2B4B] transition bg-white flex-shrink-0">
              <SlidersHorizontal size={15} className="text-[#6B6560]" />
              Filters
              {activeFilterCount > 0 && <span className="bg-[#C8965A] text-white text-xs rounded-full px-1.5 py-0.5 min-w-[18px] text-center">{activeFilterCount}</span>}
            </button>
          </div>
          <div className="flex gap-2 overflow-x-auto pb-2 mb-6">
            {cats.map(c => <button key={c} onClick={() => { setCatFilter(c); setFilterCategories([]); }} className={`px-4 py-2 rounded-full text-sm font-medium whitespace-nowrap transition flex-shrink-0 ${catFilter === c ? "bg-[#1B2B4B] text-white" : "bg-white border border-gray-200 text-[#6B6560] hover:border-[#1B2B4B]"}`}>{c}</button>)}
          </div>
          {filteredProducts.length === 0 ? (
            <div className="text-center py-20"><Search size={40} className="text-gray-200 mx-auto mb-4" /><p className="text-[#6B6560] font-medium">No products match your filters</p><button onClick={() => { setSearch(""); setCatFilter("All"); clearFilters(); }} className="mt-4 text-sm text-[#C8965A] hover:underline">Clear all filters</button></div>
          ) : (
            <>
              <div className="flex items-center justify-between mb-4"><p className="text-sm text-[#6B6560]">Showing {pagedProducts.length} of {filteredProducts.length} products</p></div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 sm:gap-6">
                {pagedProducts.map(p => (
                  <div key={p.id} className="group cursor-pointer bg-white rounded-2xl overflow-hidden shadow-sm hover:shadow-xl transition-all duration-300 border border-transparent hover:border-[#EDE8E0]" onClick={() => openProduct(p)}>
                    <div className="relative overflow-hidden aspect-square bg-gray-50">
                      <img src={p.image} alt={p.name} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                      {p.badge && <span className={`absolute top-2 left-2 text-xs font-bold px-2.5 py-1 rounded-full ${p.badge === "Sale" ? "bg-red-500 text-white" : p.badge === "New" ? "bg-[#1B2B4B] text-white" : "bg-[#C8965A] text-white"}`}>{p.badge}</span>}
                      <button onClick={e => { e.stopPropagation(); toggleWishlist(p.id); }} className="absolute top-2 right-2 w-8 h-8 rounded-full bg-white/90 flex items-center justify-center hover:bg-white transition shadow-sm"><Heart size={14} className={wishlist.includes(p.id) ? "fill-red-500 text-red-500" : "text-gray-400"} /></button>
                      <button onClick={e => { e.stopPropagation(); addToCart(p); }} className="absolute bottom-2 left-0 right-0 mx-2 bg-[#1B2B4B] text-white text-xs py-2 rounded-lg font-medium opacity-0 group-hover:opacity-100 transition-opacity duration-200 hover:bg-[#C8965A]">Quick Add</button>
                    </div>
                    <div className="p-3 sm:p-4">
                      <p className="text-xs text-[#6B6560] mb-1">{p.category}</p>
                      <p className="font-medium text-sm sm:text-base text-[#1A1410] leading-snug mb-2 line-clamp-2">{p.name}</p>
                      <div className="flex items-center gap-1 mb-2"><Stars rating={p.rating} size={10} /><span className="text-xs text-[#6B6560]">({p.reviews})</span></div>
                      <div className="flex items-center gap-2"><span className="font-bold text-[#1B2B4B]">${p.price}</span>{p.originalPrice && <span className="text-xs text-gray-400 line-through">${p.originalPrice}</span>}</div>
                    </div>
                  </div>
                ))}
              </div>
              {totalPages > 1 && (
                <div className="flex items-center justify-center gap-2 mt-12">
                  <button onClick={() => setCurrentProductPage(p => Math.max(1, p - 1))} disabled={currentProductPage === 1} className="w-10 h-10 rounded-full border border-gray-200 flex items-center justify-center hover:bg-gray-50 disabled:opacity-30 transition"><ChevronLeft size={16} /></button>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => <button key={p} onClick={() => setCurrentProductPage(p)} className={`w-10 h-10 rounded-full font-medium text-sm transition ${p === currentProductPage ? "bg-[#1B2B4B] text-white" : "border border-gray-200 hover:bg-gray-50 text-[#6B6560]"}`}>{p}</button>)}
                  <button onClick={() => setCurrentProductPage(p => Math.min(totalPages, p + 1))} disabled={currentProductPage === totalPages} className="w-10 h-10 rounded-full border border-gray-200 flex items-center justify-center hover:bg-gray-50 disabled:opacity-30 transition"><ChevronRight size={16} /></button>
                </div>
              )}
            </>
          )}
        </section>
      </div>
    );
  };

  // ─── Our Story Page ────────────────────────────────────────────────────────

  const OurStoryPage = () => (
    <div>
      <button onClick={() => goPage("shop")} className="absolute top-20 left-4 sm:left-8 z-10 bg-white/20 backdrop-blur-md text-white rounded-full px-4 py-2 flex items-center gap-2 text-sm hover:bg-white/30 transition"><ArrowLeft size={14} /> Back to Shop</button>
      <div className="relative h-[70vh] min-h-[500px] overflow-hidden">
        <img src="https://images.unsplash.com/photo-1452860606245-08befc0ff44b?w=1600&h=900&fit=crop&auto=format" alt="Craftsman" className="w-full h-full object-cover" />
        <div className="absolute inset-0 bg-gradient-to-b from-black/20 via-black/40 to-[#1B2B4B]" />
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-20 px-6 text-center">
          <p className="text-[#C8965A] text-sm tracking-[0.3em] uppercase font-medium mb-4">Est. 2018 · Portland, Oregon</p>
          <h1 className="text-white text-5xl sm:text-7xl font-serif font-bold leading-tight mb-4">Our Story</h1>
          <p className="text-white/80 text-xl max-w-2xl font-light italic">&ldquo;The world doesn&apos;t need more things. It needs better ones.&rdquo;</p>
        </div>
      </div>
      <div className="bg-[#F7F4EF]">
        <div className="max-w-4xl mx-auto px-6 py-20">
          <div className="grid md:grid-cols-2 gap-16 items-center mb-20">
            <div>
              <p className="text-[#C8965A] text-xs tracking-[0.25em] uppercase font-medium mb-4">How It Began</p>
              <h2 className="text-[#1B2B4B] text-4xl font-serif font-bold leading-tight mb-6">A frustration turned into a calling</h2>
              <p className="text-[#6B6560] leading-relaxed mb-4">In 2018, two designers — <strong className="text-[#1B2B4B]">Elara Voss</strong> and <strong className="text-[#1B2B4B]">Tomás Figueroa</strong> — left their corporate careers frustrated by a world flooded with mass-produced goods designed to be replaced, not treasured.</p>
              <p className="text-[#6B6560] leading-relaxed">They started Maison from a small studio in Portland with a simple conviction: that beauty, durability, and honest craftsmanship could coexist in everyday objects. The first collection was 12 items. All sold out in three days.</p>
            </div>
            <div className="relative">
              <img src="https://images.unsplash.com/photo-1621839673705-6617adf9e890?w=600&h=700&fit=crop&auto=format" alt="Studio" className="rounded-3xl w-full object-cover shadow-2xl" />
              <div className="absolute -bottom-5 -left-5 bg-[#C8965A] text-white rounded-2xl px-6 py-4 shadow-xl"><p className="text-3xl font-serif font-bold">2018</p><p className="text-xs opacity-80 mt-0.5">Founded in Portland</p></div>
            </div>
          </div>
        </div>
        <div className="bg-[#1B2B4B] py-20">
          <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-10 text-center">
            {[{ num: "12,400+", label: "Happy Customers" }, { num: "200+", label: "Independent Makers" }, { num: "47", label: "Countries Reached" }, { num: "6 yrs", label: "Of Curating" }].map(s => <div key={s.label}><p className="text-[#C8965A] text-4xl font-serif font-bold mb-2">{s.num}</p><p className="text-white/60 text-sm">{s.label}</p></div>)}
          </div>
        </div>
        <div className="max-w-4xl mx-auto px-6 py-20">
          <div className="grid md:grid-cols-2 gap-16 items-center">
            <div className="grid grid-cols-2 gap-4">
              <img src="https://images.unsplash.com/photo-1524592094714-0f0654e20314?w=400&h=500&fit=crop&auto=format" alt="Craft 1" className="rounded-2xl object-cover w-full h-52" />
              <img src="https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=500&fit=crop&auto=format" alt="Craft 2" className="rounded-2xl object-cover w-full h-52 mt-8" />
            </div>
            <div>
              <p className="text-[#C8965A] text-xs tracking-[0.25em] uppercase font-medium mb-4">What We Do</p>
              <h2 className="text-[#1B2B4B] text-3xl font-serif font-bold leading-tight mb-6">We find the world&apos;s most dedicated makers</h2>
              <p className="text-[#6B6560] leading-relaxed mb-4">From leather workers in Portland to ceramic artists in Kyoto, we discover independent craftspeople who pour their expertise into every piece.</p>
              <p className="text-[#6B6560] leading-relaxed">Before anything reaches our shelves, our team tests it, lives with it, and evaluates it rigorously. If we wouldn&apos;t give it as a gift to someone we love, it doesn&apos;t make the cut.</p>
            </div>
          </div>
        </div>
        <div className="bg-[#EDE8E0] py-20">
          <div className="max-w-5xl mx-auto px-6">
            <div className="text-center mb-14"><p className="text-[#C8965A] text-xs tracking-[0.25em] uppercase font-medium mb-3">What We Stand For</p><h2 className="text-[#1B2B4B] text-4xl font-serif font-bold">Our Values</h2></div>
            <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-6">
              {[{ icon: <Award size={28} className="text-[#C8965A]" />, title: "Craft Over Convenience", desc: "Hours of skilled work over automated production. Every imperfection is a signature." }, { icon: <Leaf size={28} className="text-[#C8965A]" />, title: "Sustainable Materials", desc: "Natural materials that age with grace — leather, linen, ceramics, wood, wool." }, { icon: <Users size={28} className="text-[#C8965A]" />, title: "Maker Relationships", desc: "We work directly with artisans, paying fair prices and building lasting partnerships." }, { icon: <Globe size={28} className="text-[#C8965A]" />, title: "Timeless Design", desc: "Objects that outlast trends and become more beautiful with use and age." }].map(v => <div key={v.title} className="bg-white rounded-2xl p-6 shadow-sm hover:shadow-md transition"><div className="mb-4">{v.icon}</div><h3 className="text-[#1B2B4B] font-serif font-bold mb-2">{v.title}</h3><p className="text-[#6B6560] text-sm leading-relaxed">{v.desc}</p></div>)}
            </div>
          </div>
        </div>
        <div className="max-w-3xl mx-auto px-6 py-20 text-center">
          <div className="w-16 h-0.5 bg-[#C8965A] mx-auto mb-10" />
          <p className="text-[#1B2B4B] text-2xl font-serif italic leading-relaxed mb-10">&ldquo;Every item you see on Maison has passed through our hands. We test it, use it, live with it. If we wouldn&apos;t give it as a gift to someone we love, it doesn&apos;t make the cut.&rdquo;</p>
          <div className="flex items-center justify-center gap-8">
            <div className="text-center"><img src="https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=80&h=80&fit=crop&auto=format" alt="Elara" className="w-16 h-16 rounded-full object-cover mx-auto mb-2 border-2 border-[#C8965A]" /><p className="text-[#1B2B4B] font-medium text-sm">Elara Voss</p><p className="text-[#6B6560] text-xs">Co-Founder & Creative Director</p></div>
            <div className="w-px h-14 bg-gray-200" />
            <div className="text-center"><img src="https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=80&h=80&fit=crop&auto=format" alt="Tomas" className="w-16 h-16 rounded-full object-cover mx-auto mb-2 border-2 border-[#C8965A]" /><p className="text-[#1B2B4B] font-medium text-sm">Tomás Figueroa</p><p className="text-[#6B6560] text-xs">Co-Founder & Head of Curation</p></div>
          </div>
          <button onClick={() => { productsRef.current?.scrollIntoView({ behavior: "smooth" }); goPage("shop"); }} className="mt-12 bg-[#1B2B4B] text-white px-10 py-4 rounded-full font-medium hover:bg-[#C8965A] transition text-lg">Shop the Collection</button>
        </div>
      </div>
    </div>
  );

  // ─── Product Page ──────────────────────────────────────────────────────────

  const ProductPage = () => {
    const related = ALL_PRODUCTS.filter(p => p.id !== selProduct.id && (p.category === selProduct.category || p.vendor === selProduct.vendor)).slice(0, 4);
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        <button onClick={() => goPage("shop")} className="flex items-center gap-2 text-[#6B6560] hover:text-[#1B2B4B] mb-6 text-sm transition"><ArrowLeft size={16} /> Back to Shop</button>
        <div className="grid md:grid-cols-2 gap-10 mb-16">
          <div className="relative"><div className="aspect-square rounded-3xl overflow-hidden bg-gray-50"><img src={selProduct.image} alt={selProduct.name} className="w-full h-full object-cover" /></div>{selProduct.badge && <span className={`absolute top-4 left-4 text-xs font-bold px-3 py-1.5 rounded-full ${selProduct.badge === "Sale" ? "bg-red-500 text-white" : selProduct.badge === "New" ? "bg-[#1B2B4B] text-white" : "bg-[#C8965A] text-white"}`}>{selProduct.badge}</span>}</div>
          <div className="flex flex-col">
            <p className="text-xs text-[#6B6560] uppercase tracking-widest mb-2">{selProduct.category} · {selProduct.vendor}</p>
            <h1 className="font-serif font-bold text-3xl sm:text-4xl text-[#1B2B4B] mb-3 leading-tight">{selProduct.name}</h1>
            <div className="flex items-center gap-3 mb-4"><Stars rating={selProduct.rating} size={16} /><span className="text-sm text-[#6B6560]">{selProduct.rating} ({selProduct.reviews} reviews)</span></div>
            <div className="flex items-center gap-3 mb-6"><span className="text-3xl font-bold text-[#1B2B4B]">${selProduct.price}</span>{selProduct.originalPrice && <><span className="text-lg text-gray-400 line-through">${selProduct.originalPrice}</span><span className="text-sm font-bold text-red-500">Save ${selProduct.originalPrice - selProduct.price}</span></>}</div>
            <p className="text-[#6B6560] leading-relaxed mb-6">{selProduct.description}</p>
            <div className={`inline-flex items-center gap-2 text-sm font-medium mb-6 px-3 py-1.5 rounded-full w-fit ${selProduct.stock > 10 ? "bg-emerald-50 text-emerald-700" : selProduct.stock > 0 ? "bg-amber-50 text-amber-700" : "bg-red-50 text-red-700"}`}><Package size={14} />{selProduct.stock > 10 ? "In Stock" : selProduct.stock > 0 ? `Only ${selProduct.stock} left` : "Out of Stock"}</div>
            <div className="flex items-center gap-4 mb-6">
              <div className="flex items-center border border-gray-200 rounded-xl overflow-hidden"><button onClick={() => setQty(Math.max(1, qty - 1))} className="px-4 py-2.5 hover:bg-gray-50 text-lg">−</button><span className="px-4 py-2.5 font-medium text-sm w-12 text-center">{qty}</span><button onClick={() => setQty(Math.min(selProduct.stock, qty + 1))} className="px-4 py-2.5 hover:bg-gray-50 text-lg">+</button></div>
              <button onClick={() => toggleWishlist(selProduct.id)} className="w-12 h-12 rounded-xl border border-gray-200 flex items-center justify-center hover:bg-gray-50 transition"><Heart size={18} className={wishlist.includes(selProduct.id) ? "fill-red-500 text-red-500" : "text-gray-400"} /></button>
            </div>
            <div className="flex flex-col sm:flex-row gap-3">
              <button onClick={() => addToCart(selProduct, qty)} className="flex-1 border-2 border-[#1B2B4B] text-[#1B2B4B] rounded-xl py-3.5 font-medium hover:bg-[#1B2B4B] hover:text-white transition">Add to Cart</button>
              <button onClick={buyNow} className="flex-1 bg-[#C8965A] text-white rounded-xl py-3.5 font-medium hover:bg-[#b07c45] transition shadow-md">Buy Now</button>
            </div>
            <div className="flex gap-6 mt-6 pt-6 border-t border-gray-100 text-xs text-[#6B6560]">
              <div className="flex items-center gap-1.5"><Truck size={14} className="text-[#C8965A]" />Free shipping over $150</div>
              <div className="flex items-center gap-1.5"><RotateCcw size={14} className="text-[#C8965A]" />30-day returns</div>
              <div className="flex items-center gap-1.5"><Shield size={14} className="text-[#C8965A]" />Authenticity guaranteed</div>
            </div>
          </div>
        </div>
        {related.length > 0 && <div><h2 className="font-serif font-bold text-2xl text-[#1B2B4B] mb-6">You might also like</h2><div className="grid grid-cols-2 sm:grid-cols-4 gap-4">{related.map(p => <div key={p.id} onClick={() => openProduct(p)} className="group cursor-pointer bg-white rounded-2xl overflow-hidden shadow-sm hover:shadow-md transition"><div className="aspect-square overflow-hidden"><img src={p.image} alt={p.name} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300" /></div><div className="p-3"><p className="font-medium text-sm text-[#1A1410] line-clamp-2 mb-1">{p.name}</p><p className="font-bold text-[#1B2B4B] text-sm">${p.price}</p></div></div>)}</div></div>}
      </div>
    );
  };

  // ─── Hub Page ──────────────────────────────────────────────────────────────

  const HubPage = () => (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-12">
      <div className="text-center mb-12">
        <p className="text-[#C8965A] text-xs tracking-[0.3em] uppercase font-medium mb-3">Your Dashboard</p>
        <h1 className="font-serif font-bold text-4xl text-[#1B2B4B] mb-3">Welcome back, {currentUser.firstName}</h1>
        <div className="flex items-center justify-center gap-2"><Zap size={14} className="text-[#C8965A]" /><span className="text-[#6B6560] text-sm">{currentUser.points.toLocaleString()} loyalty points · ${(currentUser.points / 100).toFixed(2)} value</span></div>
      </div>
      <div className="grid md:grid-cols-3 gap-6">
        {[
          { page: "account" as Page, icon: <User size={24} />, title: "My Account", desc: "View orders, wishlist, addresses, and loyalty rewards.", bg: "bg-[#EDE8E0]", iconHover: "group-hover:bg-[#1B2B4B]", stats: [{ label: "Total Orders", val: orders.length, color: "" }, { label: "Wishlist", val: wishlist.length, color: "" }, { label: "Points", val: currentUser.points.toLocaleString(), color: "text-[#C8965A]" }] },
          { page: "vendor" as Page, icon: <Store size={24} />, title: "Vendor Portal", desc: "Manage products, track orders, analyze profits.", bg: "bg-amber-50", iconHover: "group-hover:bg-[#C8965A]", stats: [{ label: "Revenue (MTD)", val: "$14,280", color: "text-emerald-600" }, { label: "Products", val: vendorProductsList.length, color: "" }, { label: "Pending Orders", val: "7", color: "text-amber-600" }] },
          { page: "admin" as Page, icon: <Settings size={24} />, title: "Admin Panel", desc: "Platform management, approvals, and analytics.", bg: "bg-gray-100", iconHover: "group-hover:bg-[#1B2B4B]", stats: [{ label: "Platform Revenue", val: "$528k", color: "" }, { label: "Active Vendors", val: VENDORS.filter(v => vendorStatuses[v.id] === "active").length, color: "" }, { label: "Pending", val: VENDORS.filter(v => vendorStatuses[v.id] === "pending").length, color: "text-red-500" }] },
        ].map(card => (
          <button key={card.page} onClick={() => goPage(card.page)} className="group text-left bg-white rounded-3xl p-8 shadow-sm hover:shadow-2xl border border-transparent hover:border-[#EDE8E0] transition-all duration-300">
            <div className={`w-14 h-14 rounded-2xl ${card.bg} flex items-center justify-center mb-6 ${card.iconHover} transition-colors text-[#1B2B4B] group-hover:text-white`}>{card.icon}</div>
            <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-2">{card.title}</h2>
            <p className="text-[#6B6560] text-sm leading-relaxed mb-6">{card.desc}</p>
            <div className="space-y-2 mb-6">{card.stats.map(s => <div key={s.label} className="flex justify-between text-sm"><span className="text-[#6B6560]">{s.label}</span><span className={`font-bold ${s.color || "text-[#1B2B4B]"}`}>{s.val}</span></div>)}</div>
            <div className="flex items-center gap-1.5 text-[#C8965A] text-sm font-medium">Enter Portal <ChevronRight size={16} /></div>
          </button>
        ))}
      </div>
    </div>
  );

  // ─── Account Page ──────────────────────────────────────────────────────────

  const AccountPage = () => {
    const sideNav: { key: AccTab; label: string; icon: React.ReactNode }[] = [
      { key: "overview", label: "Overview", icon: <Home size={15} /> },
      { key: "orders", label: "My Orders", icon: <Package size={15} /> },
      { key: "wishlist-alerts", label: "Wishlist & Alerts", icon: <Heart size={15} /> },
      { key: "recently-viewed", label: "Recently Viewed", icon: <Eye size={15} /> },
      { key: "loyalty", label: "Loyalty Points", icon: <Zap size={15} /> },
      { key: "addresses", label: "Addresses & Payments", icon: <MapPin size={15} /> },
      { key: "returns", label: "Returns & Refunds", icon: <RefreshCw size={15} /> },
      { key: "profile", label: "Profile", icon: <User size={15} /> },
      { key: "settings", label: "Settings", icon: <Settings size={15} /> },
      { key: "help", label: "Help & Support", icon: <HelpCircle size={15} /> },
    ];
    const wishlistProducts = ALL_PRODUCTS.filter(p => wishlist.includes(p.id));
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        <button onClick={() => goPage("hub")} className="flex items-center gap-2 text-[#6B6560] hover:text-[#1B2B4B] mb-6 text-sm transition"><ArrowLeft size={16} /> Back to Portal</button>
        <div className="flex flex-col md:flex-row gap-6">
          <aside className="md:w-64 flex-shrink-0">
            <div className="bg-white rounded-2xl p-5 shadow-sm mb-3">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-[#1B2B4B] to-[#2d4a7a] flex items-center justify-center text-white font-bold text-lg">{currentUser.firstName[0]}</div>
                <div><p className="font-bold text-[#1A1410]">{currentUser.firstName} Johnson</p><p className="text-xs text-[#6B6560]">{currentUser.email}</p></div>
              </div>
              <div className="bg-gradient-to-r from-[#1B2B4B] to-[#2d4a7a] rounded-xl p-3 mb-4 flex items-center justify-between">
                <div><p className="text-white/60 text-xs">Loyalty Points</p><p className="text-white font-bold text-xl">{currentUser.points.toLocaleString()}</p></div>
                <Zap size={24} className="text-[#C8965A]" />
              </div>
              <nav className="space-y-0.5">
                {sideNav.map(t => (
                  <button key={t.key} onClick={() => setAccTab(t.key)} className={`w-full text-left px-3 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2.5 transition ${accTab === t.key ? "bg-[#1B2B4B] text-white" : "text-[#6B6560] hover:bg-gray-50"}`}>
                    <span className="flex-shrink-0">{t.icon}</span>{t.label}
                  </button>
                ))}
                <button onClick={signOut} className="w-full text-left px-3 py-2.5 rounded-xl text-sm font-medium text-red-500 hover:bg-red-50 flex items-center gap-2.5 mt-2"><LogOut size={15} /> Sign Out</button>
              </nav>
            </div>
          </aside>
          <main className="flex-1 min-w-0">
            {/* Overview */}
            {accTab === "overview" && (
              <div className="space-y-5">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  {[{ icon: <Package size={20} />, label: "Total Orders", val: orders.length, c: "bg-blue-50 text-blue-600" }, { icon: <Truck size={20} />, label: "Shipped", val: orders.filter(o => o.status === "shipped").length, c: "bg-amber-50 text-amber-600" }, { icon: <Heart size={20} />, label: "Wishlist", val: wishlist.length, c: "bg-red-50 text-red-500" }, { icon: <Zap size={20} />, label: "Points", val: currentUser.points.toLocaleString(), c: "bg-yellow-50 text-yellow-600" }].map(s => <div key={s.label} className="bg-white rounded-2xl p-5 shadow-sm"><div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${s.c}`}>{s.icon}</div><p className="text-xl font-bold text-[#1B2B4B]">{s.val}</p><p className="text-xs text-[#6B6560]">{s.label}</p></div>)}
                </div>
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Recent Orders</h3>
                  <div className="space-y-3">
                    {orders.slice(0, 3).map(o => (
                      <div key={o.id} onClick={() => { setSelOrder(o); setAccTab("order-detail"); }} className="flex items-center gap-3 p-3 rounded-xl bg-gray-50 cursor-pointer hover:bg-[#EDE8E0] transition">
                        <img src={o.items[0].image} alt="" className="w-12 h-12 rounded-lg object-cover" />
                        <div className="flex-1 min-w-0"><p className="font-medium text-sm text-[#1A1410]">{o.id}</p><p className="text-xs text-[#6B6560]">{o.date} · ${o.total}</p></div>
                        <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${statusColor(o.status)}`}>{statusLabel(o.status)}</span>
                      </div>
                    ))}
                  </div>
                  <button onClick={() => setAccTab("orders")} className="text-sm text-[#C8965A] hover:underline mt-3 block">View all orders →</button>
                </div>
                {recentlyViewed.length > 0 && (
                  <div className="bg-white rounded-2xl p-5 shadow-sm">
                    <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Recently Viewed</h3>
                    <div className="flex gap-3 overflow-x-auto pb-1">{recentlyViewed.slice(0, 4).map(p => <div key={p.id} onClick={() => openProduct(p)} className="flex-shrink-0 w-20 cursor-pointer group"><div className="aspect-square rounded-xl overflow-hidden mb-1"><img src={p.image} alt={p.name} className="w-full h-full object-cover group-hover:scale-105 transition" /></div><p className="text-xs text-[#6B6560] truncate">{p.name.split(" ")[0]}</p></div>)}</div>
                  </div>
                )}
              </div>
            )}
            {/* Orders */}
            {accTab === "orders" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">Order History</h2>
                <div className="space-y-3">
                  {orders.map(o => (
                    <div key={o.id} className="border border-gray-100 rounded-2xl p-4 hover:border-[#1B2B4B]/20 transition">
                      <div className="flex items-start justify-between mb-3 gap-3 flex-wrap">
                        <div><p className="font-bold text-sm text-[#1A1410]">{o.id}</p><p className="text-xs text-[#6B6560]">{o.date}</p></div>
                        <span className={`text-xs font-medium px-2.5 py-1 rounded-full flex-shrink-0 ${statusColor(o.status)}`}>{statusLabel(o.status)}</span>
                      </div>
                      <div className="flex items-center gap-2 mb-3">{o.items.slice(0, 3).map((item, i) => <img key={i} src={item.image} alt="" className="w-10 h-10 rounded-lg object-cover" />)}{o.items.length > 3 && <span className="text-xs text-[#6B6560]">+{o.items.length - 3}</span>}</div>
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <span className="font-bold text-[#1B2B4B]">${o.total}</span>
                        <div className="flex gap-2 flex-wrap">
                          <button onClick={() => reorder(o)} className="text-xs px-3 py-1.5 border border-gray-200 rounded-lg hover:bg-gray-50 flex items-center gap-1 transition"><RotateCcw size={12} /> Reorder</button>
                          {(o.status === "processing" || o.status === "shipped") && <button onClick={() => openCancel(o)} className="text-xs px-3 py-1.5 border border-red-200 rounded-lg text-red-500 hover:bg-red-50 transition">Cancel Order</button>}
                          <button onClick={() => { setSelOrder(o); setAccTab("order-detail"); }} className="text-xs px-3 py-1.5 bg-[#1B2B4B] text-white rounded-lg hover:bg-[#C8965A] transition">View Details</button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {/* Order Detail */}
            {accTab === "order-detail" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <button onClick={() => setAccTab("orders")} className="flex items-center gap-2 text-[#6B6560] hover:text-[#1B2B4B] mb-5 text-sm transition"><ArrowLeft size={14} /> Back to Orders</button>
                <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
                  <div><h2 className="font-serif font-bold text-xl text-[#1B2B4B]">{selOrder.id}</h2><p className="text-sm text-[#6B6560]">Placed on {selOrder.date}</p></div>
                  <div className="flex items-center gap-2"><span className={`text-xs font-medium px-3 py-1.5 rounded-full ${statusColor(selOrder.status)}`}>{statusLabel(selOrder.status)}</span>{(selOrder.status === "processing" || selOrder.status === "shipped") && <button onClick={() => openCancel(selOrder)} className="text-xs px-3 py-1.5 border border-red-200 text-red-500 rounded-lg hover:bg-red-50 transition">Cancel Order</button>}</div>
                </div>
                {selOrder.tracking && <div className="bg-blue-50 rounded-xl p-4 mb-5 flex items-center gap-3"><Truck size={18} className="text-blue-600 flex-shrink-0" /><div><p className="text-sm font-medium text-blue-800">Tracking Number</p><p className="text-xs font-mono text-blue-700 mt-0.5">{selOrder.tracking}</p></div></div>}
                <div className="mb-5">
                  <h3 className="font-medium text-sm text-[#1A1410] mb-3">Order Progress</h3>
                  <div className="flex items-center">{["Processing", "Shipped", "Out for Delivery", "Delivered"].map((step, i) => { const idx: Record<string, number> = { processing: 0, shipped: 1, delivered: 3, cancelled: -1 }; const cur = idx[selOrder.status] ?? 0; const done = i <= cur; return <div key={step} className="flex items-center flex-1"><div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${done ? "bg-[#1B2B4B] text-white" : "bg-gray-100 text-gray-400"}`}>{done ? <Check size={12} /> : i + 1}</div>{i < 3 && <div className={`flex-1 h-0.5 ${i < cur ? "bg-[#1B2B4B]" : "bg-gray-100"}`} />}</div>; })}</div>
                </div>
                <div className="space-y-3 mb-5">{selOrder.items.map((item, i) => <div key={i} className="flex items-center gap-3 p-3 bg-gray-50 rounded-xl"><img src={item.image} alt={item.name} className="w-14 h-14 rounded-lg object-cover" /><div className="flex-1 min-w-0"><p className="font-medium text-sm">{item.name}</p><p className="text-xs text-[#6B6560]">Qty: {item.qty}</p></div><p className="font-bold text-[#1B2B4B]">${item.price}</p></div>)}</div>
                <div className="border-t border-gray-100 pt-4 space-y-2 mb-4"><div className="flex justify-between text-sm"><span className="text-[#6B6560]">Total</span><span className="font-bold text-[#1B2B4B]">${selOrder.total}</span></div></div>
                <div className="flex gap-3 flex-wrap"><button onClick={() => reorder(selOrder)} className="flex items-center gap-2 text-sm border border-gray-200 rounded-xl px-4 py-2.5 hover:bg-gray-50 transition"><RotateCcw size={14} /> Order Again</button><button className="flex items-center gap-2 text-sm border border-gray-200 rounded-xl px-4 py-2.5 hover:bg-gray-50 transition"><FileText size={14} /> Download Invoice</button></div>
              </div>
            )}
            {/* Wishlist & Alerts */}
            {accTab === "wishlist-alerts" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">Wishlist & Alerts</h2>
                {wishlistProducts.length === 0 ? <div className="text-center py-12"><Heart size={40} className="text-gray-200 mx-auto mb-3" /><p className="text-[#6B6560]">Your wishlist is empty</p><button onClick={() => goPage("shop")} className="mt-4 text-sm text-[#C8965A] hover:underline">Start shopping →</button></div> : (
                  <div className="grid sm:grid-cols-2 gap-4">
                    {wishlistProducts.map(p => (
                      <div key={p.id} className="border border-gray-100 rounded-2xl p-4 relative hover:border-[#C8965A]/30 transition">
                        {p.originalPrice && <div className="absolute -top-2 left-4 bg-red-500 text-white text-xs px-2.5 py-1 rounded-full font-bold">Price Drop! Save ${p.originalPrice - p.price}</div>}
                        <div className="flex items-start gap-3 mt-1">
                          <img src={p.image} alt={p.name} className="w-16 h-16 rounded-xl object-cover" />
                          <div className="flex-1 min-w-0"><p className="font-medium text-sm text-[#1A1410] truncate">{p.name}</p><div className="flex items-center gap-2 mt-1"><span className="font-bold text-[#1B2B4B]">${p.price}</span>{p.originalPrice && <span className="text-xs text-gray-400 line-through">${p.originalPrice}</span>}</div></div>
                        </div>
                        <div className="flex gap-2 mt-3">
                          <button onClick={() => { addToCart(p); }} className="flex-1 bg-[#1B2B4B] text-white text-xs py-2 rounded-lg hover:bg-[#C8965A] transition">Add to Cart</button>
                          <button onClick={() => toggleWishlist(p.id)} className="w-8 h-8 rounded-lg border border-gray-200 flex items-center justify-center hover:bg-red-50"><Heart size={13} className="text-red-400 fill-red-400" /></button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {/* Recently Viewed */}
            {accTab === "recently-viewed" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">Recently Viewed</h2>
                {recentlyViewed.length === 0 ? <div className="text-center py-12"><Clock size={40} className="text-gray-200 mx-auto mb-3" /><p className="text-[#6B6560]">No recently viewed products yet</p></div> : (
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {recentlyViewed.map(p => <div key={p.id} onClick={() => openProduct(p)} className="group cursor-pointer border border-gray-100 rounded-2xl overflow-hidden hover:shadow-md transition"><div className="aspect-square overflow-hidden"><img src={p.image} alt={p.name} className="w-full h-full object-cover group-hover:scale-105 transition duration-300" /></div><div className="p-3"><p className="font-medium text-sm text-[#1A1410] truncate">{p.name}</p><p className="font-bold text-[#1B2B4B] text-sm mt-0.5">${p.price}</p></div></div>)}
                  </div>
                )}
              </div>
            )}
            {/* Loyalty Points */}
            {accTab === "loyalty" && (
              <div className="space-y-4">
                <div className="bg-gradient-to-r from-[#1B2B4B] to-[#2d4a7a] rounded-3xl p-6 text-white">
                  <div className="flex items-center justify-between mb-4"><div><p className="text-white/60 text-sm">Available Points</p><p className="text-5xl font-serif font-bold mt-1">{currentUser.points.toLocaleString()}</p></div><Zap size={48} className="text-[#C8965A] opacity-60" /></div>
                  <div className="grid grid-cols-3 gap-4 mt-6 pt-6 border-t border-white/10">
                    <div><p className="text-white/50 text-xs">Cash Value</p><p className="text-white font-bold">${(currentUser.points / 100).toFixed(2)}</p></div>
                    <div><p className="text-white/50 text-xs">Tier</p><p className="text-[#C8965A] font-bold">Gold</p></div>
                    <div><p className="text-white/50 text-xs">Earn Rate</p><p className="text-white font-bold">10 pts/$1</p></div>
                  </div>
                </div>
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">How to Earn</h3>
                  <div className="grid sm:grid-cols-3 gap-3">
                    {[{ icon: <ShoppingBag size={20} />, title: "Make a Purchase", pts: "10 pts per $1" }, { icon: <Star size={20} />, title: "Leave a Review", pts: "+50 pts" }, { icon: <Users size={20} />, title: "Refer a Friend", pts: "+200 pts" }].map(r => <div key={r.title} className="bg-gray-50 rounded-xl p-4"><div className="text-[#C8965A] mb-2">{r.icon}</div><p className="font-medium text-sm">{r.title}</p><p className="text-xs text-emerald-600 font-bold mt-0.5">{r.pts}</p></div>)}
                  </div>
                </div>
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Transaction History</h3>
                  <div className="space-y-3">
                    {loyaltyTx.map((t, i) => <div key={i} className="flex items-center justify-between py-3 border-b border-gray-50 last:border-0"><div><p className="font-medium text-sm">{t.desc}</p><p className="text-xs text-[#6B6560]">{t.date}</p></div><span className={`font-bold text-sm ${t.type === "earn" ? "text-emerald-600" : "text-red-500"}`}>{t.type === "earn" ? "+" : ""}{t.pts} pts</span></div>)}
                  </div>
                </div>
              </div>
            )}
            {/* Addresses & Payments */}
            {accTab === "addresses" && (
              <div className="space-y-4">
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-4"><h2 className="font-serif font-bold text-xl text-[#1B2B4B]">Saved Addresses</h2><button className="flex items-center gap-2 text-sm text-[#C8965A] hover:underline"><Plus size={14} /> Add New</button></div>
                  <div className="grid sm:grid-cols-2 gap-4">
                    {savedAddresses.map(addr => <div key={addr.id} className="border border-gray-100 rounded-2xl p-4 relative hover:border-[#1B2B4B]/20 transition">{addr.isDefault && <span className="absolute top-3 right-3 text-xs bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded-full font-medium">Default</span>}<p className="font-bold text-sm text-[#1B2B4B] mb-1">{addr.label}</p><p className="text-sm text-[#1A1410]">{addr.name}</p><p className="text-sm text-[#6B6560]">{addr.street}, {addr.city}, {addr.state} {addr.pincode}</p><p className="text-sm text-[#6B6560]">{addr.phone}</p><div className="flex gap-2 mt-3"><button className="text-xs px-3 py-1.5 border border-gray-200 rounded-lg hover:bg-gray-50 flex items-center gap-1 transition"><Edit size={11} /> Edit</button>{!addr.isDefault && <button onClick={() => setSavedAddresses(prev => prev.map(a => ({ ...a, isDefault: a.id === addr.id })))} className="text-xs px-3 py-1.5 border border-gray-200 rounded-lg hover:bg-gray-50 transition">Set Default</button>}<button onClick={() => setSavedAddresses(prev => prev.filter(a => a.id !== addr.id))} className="text-xs px-3 py-1.5 border border-red-100 text-red-400 rounded-lg hover:bg-red-50 transition"><Trash2 size={11} /></button></div></div>)}
                  </div>
                </div>
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-4"><h2 className="font-serif font-bold text-xl text-[#1B2B4B]">Payment Methods</h2><button className="flex items-center gap-2 text-sm text-[#C8965A] hover:underline"><Plus size={14} /> Add New</button></div>
                  <div className="space-y-3">
                    {savedPayments.map(pm => <div key={pm.id} className="flex items-center gap-3 p-4 border border-gray-100 rounded-2xl hover:border-[#1B2B4B]/20 transition">{pm.type === "card" ? <CreditCard size={22} className="text-[#1B2B4B]" /> : <Smartphone size={22} className="text-[#C8965A]" />}<div className="flex-1"><p className="font-medium text-sm">{pm.label}</p>{pm.isDefault && <span className="text-xs text-emerald-600">Default</span>}</div><button onClick={() => setSavedPayments(prev => prev.filter(p => p.id !== pm.id))} className="text-red-400 hover:text-red-600"><Trash2 size={15} /></button></div>)}
                  </div>
                </div>
              </div>
            )}
            {/* Returns */}
            {accTab === "returns" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">Returns & Refunds</h2>
                <div className="bg-blue-50 rounded-xl p-4 mb-5 flex items-start gap-3"><Shield size={18} className="text-blue-600 flex-shrink-0 mt-0.5" /><div><p className="text-blue-800 font-medium text-sm">30-Day Return Policy</p><p className="text-blue-700 text-xs mt-1">All items can be returned within 30 days of delivery. Must be unused and in original packaging.</p></div></div>
                <h3 className="font-medium text-sm text-[#1A1410] mb-3">Eligible for Return</h3>
                <div className="space-y-3">
                  {orders.filter(o => o.status === "delivered").map(o => (
                    <div key={o.id} className="border border-gray-100 rounded-2xl p-4">
                      <div className="flex items-start justify-between mb-2"><div><p className="font-bold text-sm">{o.id}</p><p className="text-xs text-[#6B6560]">Delivered · {o.date}</p></div><button className="text-xs px-3 py-1.5 bg-[#1B2B4B] text-white rounded-lg hover:bg-[#C8965A] transition">Request Return</button></div>
                      <div className="flex gap-2">{o.items.map((item, i) => <img key={i} src={item.image} alt="" className="w-10 h-10 rounded-lg object-cover" />)}</div>
                    </div>
                  ))}
                  {orders.filter(o => o.status === "delivered").length === 0 && <p className="text-[#6B6560] text-sm text-center py-8">No delivered orders eligible for return.</p>}
                </div>
              </div>
            )}
            {/* Profile */}
            {accTab === "profile" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-6">Profile</h2>
                <div className="grid sm:grid-cols-2 gap-4 mb-6">{[["First Name", "Alex"], ["Last Name", "Johnson"], ["Email", "alex@example.com"], ["Phone", "+1 503 555 0142"]].map(([label, val]) => <div key={label}><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-1.5">{label}</label><input defaultValue={val} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white outline-none focus:border-[#1B2B4B]" /></div>)}</div>
                <button className="bg-[#1B2B4B] text-white px-6 py-2.5 rounded-xl text-sm font-medium hover:bg-[#C8965A] transition">Save Changes</button>
              </div>
            )}
            {/* Settings */}
            {accTab === "settings" && (
              <div className="bg-white rounded-2xl p-5 shadow-sm">
                <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-6">Settings</h2>
                {[["Email Notifications", "Receive order updates and promotions"], ["SMS Alerts", "Get text alerts for shipment tracking"], ["Price Drop Alerts", "Be notified when wishlist items go on sale"], ["Marketing Emails", "Hear about new products and sales"]].map(([label, desc]) => <div key={label} className="flex items-center justify-between py-4 border-b border-gray-50"><div><p className="font-medium text-sm">{label}</p><p className="text-xs text-[#6B6560]">{desc}</p></div><button className="w-11 h-6 bg-[#1B2B4B] rounded-full relative flex-shrink-0"><div className="absolute top-1 right-1 w-4 h-4 bg-white rounded-full" /></button></div>)}
              </div>
            )}
            {/* Help & Support */}
            {accTab === "help" && (
              <div className="space-y-4">
                <div className="grid sm:grid-cols-3 gap-4">
                  {[{ icon: <MessageCircle size={24} className="text-[#C8965A]" />, title: "Live Chat", desc: "Chat with our support team now", action: "Start Chat", color: "bg-orange-50" }, { icon: <Phone size={24} className="text-blue-600" />, title: "Phone Support", desc: "+1 800 MAISON (Mon–Fri, 9–6 PST)", action: "Call Now", color: "bg-blue-50" }, { icon: <FileText size={24} className="text-emerald-600" />, title: "Email Support", desc: "We reply within 24 hours", action: "Send Email", color: "bg-emerald-50" }].map(c => <div key={c.title} className={`${c.color} rounded-2xl p-5`}><div className="mb-3">{c.icon}</div><h3 className="font-bold text-sm text-[#1A1410] mb-1">{c.title}</h3><p className="text-xs text-[#6B6560] mb-3">{c.desc}</p><button className="text-xs font-medium text-[#1B2B4B] hover:text-[#C8965A] transition">{c.action} →</button></div>)}
                </div>
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Frequently Asked Questions</h3>
                  <div className="space-y-2">
                    {[["How do I track my order?", "Go to My Account → My Orders and click on your order to see the tracking number and estimated delivery date."], ["What is your return policy?", "We offer free returns within 30 days of delivery for all items in original condition."], ["Do you offer international shipping?", "Yes, we ship to 47+ countries. Shipping rates and times vary by location."], ["How do I use my loyalty points?", "At checkout, enable 'Redeem Points' to apply up to 20% of your order total as a discount (100 pts = $1)."], ["Can I change or cancel my order?", "Orders can be cancelled from My Orders page while in 'Processing' status for a full refund, or 'Shipped' for an 85% refund."]].map(([q, a]) => {
                      const [open, setOpen] = useState(false);
                      return (
                        <div key={q} className="border border-gray-100 rounded-xl overflow-hidden">
                          <button onClick={() => setOpen(v => !v)} className="w-full text-left px-4 py-3.5 flex items-center justify-between hover:bg-gray-50 transition"><span className="font-medium text-sm text-[#1A1410]">{q}</span><ChevronDown size={16} className={`text-[#6B6560] transition-transform flex-shrink-0 ${open ? "rotate-180" : ""}`} /></button>
                          {open && <div className="px-4 pb-4 text-sm text-[#6B6560] leading-relaxed border-t border-gray-50 pt-3">{a}</div>}
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="bg-white rounded-2xl p-5 shadow-sm">
                  <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Quick Links</h3>
                  <div className="grid sm:grid-cols-2 gap-3">
                    {[{ icon: <Package size={16} />, text: "Track my order", action: () => setAccTab("orders") }, { icon: <RefreshCw size={16} />, text: "Request a return", action: () => setAccTab("returns") }, { icon: <Truck size={16} />, text: "Shipping information", action: () => {} }, { icon: <Shield size={16} />, text: "Authenticity guarantee", action: () => {} }].map(l => <button key={l.text} onClick={l.action} className="flex items-center gap-2.5 p-3 border border-gray-100 rounded-xl hover:border-[#1B2B4B]/20 hover:bg-gray-50 transition text-sm text-[#1A1410]"><span className="text-[#C8965A]">{l.icon}</span>{l.text}</button>)}
                  </div>
                </div>
              </div>
            )}
          </main>
        </div>
      </div>
    );
  };

  // ─── Vendor Page ───────────────────────────────────────────────────────────

  const VendorPage = () => {
    const maxRev = Math.max(...analyticsData.map(p => p.revenue), 1);
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        <button onClick={() => goPage("hub")} className="flex items-center gap-2 text-[#6B6560] hover:text-[#1B2B4B] mb-6 text-sm transition"><ArrowLeft size={16} /> Back to Portal</button>
        <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
          <div><h1 className="font-serif font-bold text-2xl sm:text-3xl text-[#1B2B4B]">Artisan Goods Co.</h1><p className="text-[#6B6560] text-sm">Vendor Dashboard · Marcus Holloway</p></div>
          <div className="flex gap-2">
            <button onClick={() => setCsvUploadOpen(true)} className="flex items-center gap-2 border border-[#1B2B4B] text-[#1B2B4B] px-4 py-2.5 rounded-xl text-sm font-medium hover:bg-[#1B2B4B] hover:text-white transition"><Upload size={15} /> Bulk Upload</button>
            <button onClick={() => setAddProductOpen(true)} className="flex items-center gap-2 bg-[#C8965A] text-white px-4 py-2.5 rounded-xl text-sm font-medium hover:bg-[#b07c45] transition shadow-sm"><Plus size={15} /> Add Product</button>
          </div>
        </div>
        <div className="flex overflow-x-auto gap-1 mb-6 pb-1">
          {(["overview", "products", "orders", "analytics"] as VendorTab[]).map(t => <button key={t} onClick={() => setVendorTab(t)} className={`px-5 py-2.5 rounded-xl text-sm font-medium whitespace-nowrap capitalize transition ${vendorTab === t ? "bg-[#1B2B4B] text-white" : "text-[#6B6560] hover:bg-gray-100"}`}>{t}</button>)}
        </div>
        {vendorTab === "overview" && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[{ label: "Monthly Revenue", val: "$14,280", sub: "+12%", icon: <DollarSign size={20} />, c: "bg-emerald-50 text-emerald-600" }, { label: "Total Orders", val: "1,823", sub: "All time", icon: <Package size={20} />, c: "bg-blue-50 text-blue-600" }, { label: "Active Products", val: vendorProductsList.filter(p => p.stock > 0).length.toString(), sub: `${vendorProductsList.length} total`, icon: <Tag size={20} />, c: "bg-amber-50 text-amber-600" }, { label: "Avg. Rating", val: "4.8", sub: "All products", icon: <Star size={20} />, c: "bg-yellow-50 text-yellow-600" }].map(s => <div key={s.label} className="bg-white rounded-2xl p-5 shadow-sm"><div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${s.c}`}>{s.icon}</div><p className="text-xl font-bold text-[#1B2B4B]">{s.val}</p><p className="text-xs text-[#6B6560]">{s.label}</p><p className="text-xs text-emerald-600 mt-0.5">{s.sub}</p></div>)}
            </div>
            <div className="bg-white rounded-2xl p-5 shadow-sm">
              <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Recent Orders</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm min-w-[500px]"><thead><tr className="border-b border-gray-100">{["Order ID", "Date", "Total", "Status", "Action"].map(h => <th key={h} className="text-left py-3 pr-4 text-xs text-[#6B6560] uppercase tracking-wide font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-gray-50">{ORDERS_INIT.map(o => <tr key={o.id} className="hover:bg-gray-50"><td className="py-3 pr-4 font-mono text-xs">{o.id}</td><td className="py-3 pr-4 text-[#6B6560] text-xs">{o.date}</td><td className="py-3 pr-4 font-bold text-[#1B2B4B]">${o.total}</td><td className="py-3 pr-4"><span className={`text-xs font-medium px-2.5 py-1 rounded-full ${statusColor(vendorOrderStatuses[o.id] ?? o.status)}`}>{statusLabel(vendorOrderStatuses[o.id] ?? o.status)}</span></td><td className="py-3"><button onClick={() => openManageOrder(o)} className="text-xs px-3 py-1.5 bg-[#1B2B4B] text-white rounded-lg hover:bg-[#C8965A] transition">Manage</button></td></tr>)}</tbody>
                </table>
              </div>
            </div>
          </div>
        )}
        {vendorTab === "products" && (
          <div className="bg-white rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4"><h2 className="font-serif font-bold text-xl text-[#1B2B4B]">Your Products</h2><span className="text-sm text-[#6B6560]">{vendorProductsList.length} products</span></div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {vendorProductsList.map(p => <div key={p.id} className="border border-gray-100 rounded-2xl p-4 hover:border-[#C8965A]/30 transition"><div className="flex items-start gap-3"><img src={p.image} alt={p.name} className="w-16 h-16 rounded-xl object-cover flex-shrink-0" /><div className="flex-1 min-w-0"><p className="font-medium text-sm truncate">{p.name}</p><p className="text-xs text-[#6B6560]">{p.category}</p><p className="font-bold text-[#C8965A] mt-1">${p.price}</p></div></div><div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-50"><span className={`text-xs font-medium px-2 py-1 rounded-full ${p.stock > 10 ? "bg-emerald-50 text-emerald-700" : p.stock > 0 ? "bg-amber-50 text-amber-700" : "bg-red-50 text-red-600"}`}>{p.stock > 10 ? "In Stock" : p.stock > 0 ? `Low (${p.stock})` : "Out of Stock"}</span><div className="flex gap-1"><button className="w-8 h-8 rounded-lg border border-gray-200 flex items-center justify-center hover:bg-gray-50"><Edit size={13} className="text-[#6B6560]" /></button><button onClick={() => setVendorProductsList(prev => prev.filter(x => x.id !== p.id))} className="w-8 h-8 rounded-lg border border-gray-200 flex items-center justify-center hover:bg-red-50"><Trash2 size={13} className="text-red-400" /></button></div></div></div>)}
            </div>
          </div>
        )}
        {vendorTab === "orders" && (
          <div className="bg-white rounded-2xl p-5 shadow-sm">
            <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">All Orders</h2>
            <div className="space-y-3">
              {ORDERS_INIT.map(o => <div key={o.id} className="border border-gray-100 rounded-2xl p-4"><div className="flex items-start justify-between mb-3 gap-3 flex-wrap"><div><p className="font-bold text-sm">{o.id}</p><p className="text-xs text-[#6B6560]">{o.date} · {o.address}</p></div><div className="flex items-center gap-2"><span className={`text-xs font-medium px-2.5 py-1 rounded-full ${statusColor(vendorOrderStatuses[o.id] ?? o.status)}`}>{statusLabel(vendorOrderStatuses[o.id] ?? o.status)}</span><button onClick={() => openManageOrder(o)} className="text-xs px-3 py-1.5 bg-[#1B2B4B] text-white rounded-lg hover:bg-[#C8965A] transition">Manage</button></div></div><div className="flex items-center gap-2">{o.items.map((item, i) => <img key={i} src={item.image} alt="" className="w-10 h-10 rounded-lg object-cover" />)}<span className="text-sm font-bold text-[#1B2B4B] ml-auto">${o.total}</span></div></div>)}
            </div>
          </div>
        )}
        {vendorTab === "analytics" && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              {[{ label: "Most Profitable", val: analyticsData[0]?.name.split(" ").slice(0, 2).join(" ") ?? "—", sub: `$${analyticsData[0]?.profit.toLocaleString()} profit`, icon: <TrendingUp size={20} className="text-emerald-600" />, bg: "bg-emerald-50" }, { label: "Best Seller", val: [...analyticsData].sort((a, b) => b.totalOrders - a.totalOrders)[0]?.name.split(" ").slice(0, 2).join(" ") ?? "—", sub: `${[...analyticsData].sort((a, b) => b.totalOrders - a.totalOrders)[0]?.totalOrders ?? 0} orders`, icon: <BarChart2 size={20} className="text-blue-600" />, bg: "bg-blue-50" }, { label: "Low Stock Alerts", val: `${vendorProductsList.filter(p => p.stock > 0 && p.stock <= 10).length} products`, sub: "Need restocking", icon: <AlertTriangle size={20} className="text-amber-600" />, bg: "bg-amber-50" }].map(s => <div key={s.label} className="bg-white rounded-2xl p-5 shadow-sm"><div className={`w-10 h-10 rounded-xl ${s.bg} flex items-center justify-center mb-3`}>{s.icon}</div><p className="font-bold text-[#1B2B4B] truncate">{s.val}</p><p className="text-xs text-[#6B6560]">{s.label}</p><p className="text-xs text-[#C8965A] mt-0.5">{s.sub}</p></div>)}
            </div>
            <div className="bg-white rounded-2xl p-5 shadow-sm">
              <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Product Performance</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm min-w-[700px]"><thead><tr className="border-b border-gray-100">{["#", "Product", "Orders", "Revenue", "Profit (35%)", "Stock", "Rating"].map(h => <th key={h} className="text-left py-3 pr-4 text-xs text-[#6B6560] uppercase font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-gray-50">{analyticsData.map((p, i) => <tr key={p.id} className={`hover:bg-gray-50 ${i === 0 ? "bg-amber-50/40" : ""}`}><td className="py-3 pr-4">{i === 0 ? <span className="text-[#C8965A] font-bold">★</span> : <span className="text-[#6B6560] text-xs">{i + 1}</span>}</td><td className="py-3 pr-4"><div className="flex items-center gap-2"><img src={p.image} alt={p.name} className="w-9 h-9 rounded-lg object-cover" /><div><p className="font-medium text-xs max-w-[120px] truncate">{p.name}</p><p className="text-[#6B6560] text-xs">{p.category}</p></div></div></td><td className="py-3 pr-4 font-bold text-[#1B2B4B]">{p.totalOrders.toLocaleString()}</td><td className="py-3 pr-4">${p.revenue.toLocaleString()}</td><td className="py-3 pr-4 font-bold text-emerald-600">${p.profit.toLocaleString()}</td><td className="py-3 pr-4"><span className={`text-xs font-medium px-2 py-1 rounded-full ${p.stockStatus === "in-stock" ? "bg-emerald-50 text-emerald-700" : p.stockStatus === "low-stock" ? "bg-amber-50 text-amber-700" : "bg-red-50 text-red-600"}`}>{p.stockStatus === "in-stock" ? `In Stock (${p.stock})` : p.stockStatus === "low-stock" ? `Low (${p.stock})` : "Out of Stock"}</span></td><td className="py-3"><div className="flex items-center gap-1"><Star size={12} className="fill-[#C8965A] text-[#C8965A]" /><span className="text-xs">{p.rating}</span></div></td></tr>)}</tbody>
                </table>
              </div>
            </div>
            <div className="bg-white rounded-2xl p-5 shadow-sm">
              <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-5">Revenue by Product</h3>
              <div className="space-y-3">{analyticsData.slice(0, 8).map(p => <div key={p.id}><div className="flex justify-between text-xs mb-1"><span className="text-[#1A1410] font-medium truncate max-w-[200px]">{p.name}</span><span className="text-[#6B6560] ml-2 flex-shrink-0">${p.revenue.toLocaleString()}</span></div><div className="h-2 bg-gray-100 rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-[#1B2B4B] to-[#C8965A] rounded-full transition-all duration-700" style={{ width: `${Math.round((p.revenue / maxRev) * 100)}%` }} /></div></div>)}</div>
            </div>
          </div>
        )}
      </div>
    );
  };

  // ─── Admin Page ────────────────────────────────────────────────────────────

  const AdminPage = () => (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
      <button onClick={() => goPage("hub")} className="flex items-center gap-2 text-[#6B6560] hover:text-[#1B2B4B] mb-6 text-sm transition"><ArrowLeft size={16} /> Back to Portal</button>
      <div className="flex items-center justify-between mb-6"><div><h1 className="font-serif font-bold text-2xl sm:text-3xl text-[#1B2B4B]">Admin Panel</h1><p className="text-[#6B6560] text-sm">Platform Management · Super Admin</p></div><span className="bg-red-100 text-red-700 text-xs font-bold px-3 py-1.5 rounded-full">Admin Access</span></div>
      <div className="flex overflow-x-auto gap-1 mb-6 pb-1">
        {(["overview", "vendors", "products", "orders", "commission", "coupons"] as AdminTab[]).map(t => <button key={t} onClick={() => setAdminTab(t)} className={`px-5 py-2.5 rounded-xl text-sm font-medium whitespace-nowrap capitalize transition ${adminTab === t ? "bg-[#1B2B4B] text-white" : "text-[#6B6560] hover:bg-gray-100"}`}>{t}</button>)}
      </div>
      {adminTab === "overview" && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[{ label: "Total Revenue", val: "$528k", icon: <DollarSign size={20} />, c: "bg-emerald-50 text-emerald-600" }, { label: "Active Vendors", val: VENDORS.filter(v => vendorStatuses[v.id] === "active").length, icon: <Store size={20} />, c: "bg-blue-50 text-blue-600" }, { label: "Products Listed", val: ALL_PRODUCTS.length, icon: <Package size={20} />, c: "bg-amber-50 text-amber-600" }, { label: "Pending Approvals", val: VENDORS.filter(v => vendorStatuses[v.id] === "pending").length, icon: <Bell size={20} />, c: "bg-red-50 text-red-500" }].map(s => <div key={s.label} className="bg-white rounded-2xl p-5 shadow-sm"><div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${s.c}`}>{s.icon}</div><p className="text-2xl font-bold text-[#1B2B4B]">{s.val}</p><p className="text-xs text-[#6B6560]">{s.label}</p></div>)}
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-white rounded-2xl p-5 shadow-sm"><h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Pending Approvals</h3>{VENDORS.filter(v => vendorStatuses[v.id] === "pending").length === 0 ? <p className="text-[#6B6560] text-sm text-center py-4">No pending approvals.</p> : VENDORS.filter(v => vendorStatuses[v.id] === "pending").map(v => <div key={v.id} className="flex items-center gap-3 p-3 rounded-xl bg-amber-50 mb-2"><div className="w-10 h-10 rounded-full bg-[#1B2B4B] flex items-center justify-center text-white font-bold text-sm">{v.name[0]}</div><div className="flex-1 min-w-0"><p className="font-medium text-sm">{v.store}</p><p className="text-xs text-[#6B6560]">{v.name} · {v.joined}</p></div><div className="flex gap-2"><button onClick={() => approveVendor(v.id)} className="text-xs px-2.5 py-1.5 bg-emerald-600 text-white rounded-lg">Approve</button><button onClick={() => suspendVendor(v.id)} className="text-xs px-2.5 py-1.5 bg-red-500 text-white rounded-lg">Reject</button></div></div>)}</div>
            <div className="bg-white rounded-2xl p-5 shadow-sm"><h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Commission Overview</h3><div className="flex items-center justify-between mb-3"><span className="text-sm text-[#6B6560]">Current Rate</span><span className="text-2xl font-bold text-[#1B2B4B]">{commissionRate}%</span></div><div className="space-y-2">{[{ label: "Total Revenue (Platform)", val: "$528,540" }, { label: "Commission Earned", val: `$${Math.round(528540 * commissionRate / 100).toLocaleString()}` }, { label: "Vendor Payouts", val: `$${Math.round(528540 * (100 - commissionRate) / 100).toLocaleString()}` }].map(r => <div key={r.label} className="flex justify-between text-sm"><span className="text-[#6B6560]">{r.label}</span><span className="font-bold text-[#1B2B4B]">{r.val}</span></div>)}</div><button onClick={() => setAdminTab("commission")} className="mt-4 text-xs text-[#C8965A] hover:underline">Manage commission settings →</button></div>
          </div>
        </div>
      )}
      {adminTab === "vendors" && (
        <div className="bg-white rounded-2xl p-5 shadow-sm">
          <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">All Vendors</h2>
          <div className="overflow-x-auto"><table className="w-full text-sm min-w-[700px]"><thead><tr className="border-b border-gray-100">{["Vendor", "Store", "Products", "Revenue", "Rating", "Status", "Actions"].map(h => <th key={h} className="text-left py-3 pr-4 text-xs text-[#6B6560] uppercase font-medium">{h}</th>)}</tr></thead><tbody className="divide-y divide-gray-50">{VENDORS.map(v => <tr key={v.id} className="hover:bg-gray-50"><td className="py-3 pr-4"><div className="flex items-center gap-2"><div className="w-8 h-8 rounded-full bg-[#1B2B4B] flex items-center justify-center text-white text-xs font-bold">{v.name[0]}</div><div><p className="font-medium">{v.name}</p><p className="text-xs text-[#6B6560]">{v.joined}</p></div></div></td><td className="py-3 pr-4 text-[#6B6560]">{v.store}</td><td className="py-3 pr-4">{v.products}</td><td className="py-3 pr-4 font-bold text-[#1B2B4B]">${v.revenue.toLocaleString()}</td><td className="py-3 pr-4"><div className="flex items-center gap-1"><Star size={12} className="fill-[#C8965A] text-[#C8965A]" /><span>{v.rating}</span></div></td><td className="py-3 pr-4"><span className={`text-xs font-medium px-2.5 py-1 rounded-full ${vendorStatusColor(vendorStatuses[v.id] ?? v.status)}`}>{vendorStatuses[v.id] ?? v.status}</span></td><td className="py-3"><div className="flex gap-1">{vendorStatuses[v.id] !== "active" && <button onClick={() => approveVendor(v.id)} className="text-xs px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-lg hover:bg-emerald-100">Approve</button>}{vendorStatuses[v.id] !== "suspended" && <button onClick={() => suspendVendor(v.id)} className="text-xs px-2.5 py-1 bg-red-50 text-red-600 rounded-lg hover:bg-red-100">Suspend</button>}</div></td></tr>)}</tbody></table></div>
        </div>
      )}
      {adminTab === "products" && (
        <div className="bg-white rounded-2xl p-5 shadow-sm">
          <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">All Products</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">{ALL_PRODUCTS.map(p => <div key={p.id} className="border border-gray-100 rounded-2xl p-4"><div className="flex items-start gap-3"><img src={p.image} alt={p.name} className="w-14 h-14 rounded-xl object-cover" /><div className="flex-1 min-w-0"><p className="font-medium text-sm truncate">{p.name}</p><p className="text-xs text-[#6B6560]">{p.vendor}</p><p className="font-bold text-[#C8965A] mt-1">${p.price}</p></div></div><div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-50"><div className="flex items-center gap-1"><Stars rating={p.rating} size={10} /><span className="text-xs text-[#6B6560]">({p.reviews})</span></div><div className="flex gap-1"><button className="w-7 h-7 rounded-lg border border-gray-200 flex items-center justify-center hover:bg-gray-50"><Eye size={12} className="text-[#6B6560]" /></button><button className="w-7 h-7 rounded-lg border border-gray-200 flex items-center justify-center hover:bg-red-50"><Trash2 size={12} className="text-red-400" /></button></div></div></div>)}</div>
        </div>
      )}
      {adminTab === "orders" && (
        <div className="bg-white rounded-2xl p-5 shadow-sm">
          <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">Platform Orders</h2>
          <div className="space-y-3">{orders.map(o => <div key={o.id} className="flex items-center gap-3 p-3 rounded-xl border border-gray-100"><img src={o.items[0].image} alt="" className="w-12 h-12 rounded-xl object-cover" /><div className="flex-1 min-w-0"><p className="font-bold text-sm">{o.id}</p><p className="text-xs text-[#6B6560]">{o.date} · {o.items.length} item{o.items.length > 1 ? "s" : ""}</p></div><div className="text-right flex-shrink-0"><p className="font-bold text-sm">${o.total}</p><span className={`text-xs font-medium px-2 py-0.5 rounded-full ${statusColor(o.status)}`}>{statusLabel(o.status)}</span></div></div>)}</div>
        </div>
      )}
      {adminTab === "commission" && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl p-6 shadow-sm">
            <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-2">Commission Settings</h2>
            <p className="text-[#6B6560] text-sm mb-6">Set the percentage Maison takes from each vendor sale. Changes apply to all future transactions.</p>
            <div className="flex items-center gap-6 mb-6">
              <div className="w-24 h-24 rounded-full bg-gradient-to-br from-[#1B2B4B] to-[#2d4a7a] flex items-center justify-center"><p className="text-white text-3xl font-bold">{commissionRate}%</p></div>
              <div className="flex-1"><p className="text-sm font-medium text-[#1A1410] mb-3">Platform Commission Rate</p><input type="range" min={5} max={30} step={1} value={commissionRate} onChange={e => setCommissionRate(+e.target.value)} className="w-full accent-[#1B2B4B] cursor-pointer" /><div className="flex justify-between text-xs text-[#6B6560] mt-1"><span>5% (Minimum)</span><span>30% (Maximum)</span></div></div>
            </div>
            <div className="grid sm:grid-cols-3 gap-4 bg-gray-50 rounded-2xl p-5">
              {[{ label: "Platform Revenue", val: `$${Math.round(528540 * commissionRate / 100).toLocaleString()}`, desc: `${commissionRate}% commission` }, { label: "Vendor Payout", val: `$${Math.round(528540 * (100 - commissionRate) / 100).toLocaleString()}`, desc: `${100 - commissionRate}% of sales` }, { label: "Net GMV", val: "$528,540", desc: "Gross merchandise value" }].map(r => <div key={r.label}><p className="text-xs text-[#6B6560] mb-1">{r.label}</p><p className="text-xl font-bold text-[#1B2B4B]">{r.val}</p><p className="text-xs text-[#6B6560]">{r.desc}</p></div>)}
            </div>
            <button className="mt-4 bg-[#1B2B4B] text-white px-6 py-2.5 rounded-xl text-sm font-medium hover:bg-[#C8965A] transition">Save Commission Rate</button>
          </div>
        </div>
      )}
      {adminTab === "coupons" && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl p-6 shadow-sm">
            <h2 className="font-serif font-bold text-xl text-[#1B2B4B] mb-5">Create Discount / Coupon</h2>
            <div className="grid sm:grid-cols-2 gap-4 mb-4">
              <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Coupon Code</label><input value={newCoupon.code} onChange={e => setNewCoupon(c => ({ ...c, code: e.target.value.toUpperCase() }))} placeholder="e.g. SAVE20" className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B] uppercase font-mono" /></div>
              <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Discount Amount</label><input type="number" value={newCoupon.discount} onChange={e => setNewCoupon(c => ({ ...c, discount: e.target.value }))} placeholder="0" className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-[#1B2B4B]" /></div>
              <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Discount Type</label><select value={newCoupon.type} onChange={e => setNewCoupon(c => ({ ...c, type: e.target.value }))} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white"><option value="percent">Percentage (%)</option><option value="flat">Flat Amount (₹)</option></select></div>
              <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Applies To</label><select value={newCoupon.scope} onChange={e => setNewCoupon(c => ({ ...c, scope: e.target.value }))} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white"><option value="all">All Products</option>{allCategories.map(cat => <option key={cat}>{cat}</option>)}</select></div>
              <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Expiry Date</label><input type="date" value={newCoupon.expires} onChange={e => setNewCoupon(c => ({ ...c, expires: e.target.value }))} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white outline-none focus:border-[#1B2B4B]" /></div>
            </div>
            <button onClick={addCoupon} className="flex items-center gap-2 bg-[#C8965A] text-white px-5 py-2.5 rounded-xl text-sm font-medium hover:bg-[#b07c45] transition"><Ticket size={15} /> Create Coupon</button>
          </div>
          <div className="bg-white rounded-2xl p-5 shadow-sm">
            <h3 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Active Coupons</h3>
            <div className="space-y-3">{coupons.map(c => <div key={c.id} className={`border rounded-2xl p-4 transition ${c.active ? "border-gray-100" : "border-gray-100 opacity-50"}`}><div className="flex items-center justify-between flex-wrap gap-2"><div className="flex items-center gap-3"><div className="bg-[#1B2B4B] text-white font-mono font-bold px-3 py-1.5 rounded-lg text-sm">{c.code}</div><div><p className="font-medium text-sm">{c.discount}{c.type === "percent" ? "% off" : " ₹ off"} · {c.scope === "all" ? "All products" : c.scope}</p><p className="text-xs text-[#6B6560]">Expires {c.expires} · {c.uses} uses</p></div></div><div className="flex items-center gap-2"><span className={`text-xs px-2 py-1 rounded-full font-medium ${c.active ? "bg-emerald-50 text-emerald-700" : "bg-gray-100 text-gray-500"}`}>{c.active ? "Active" : "Inactive"}</span><button onClick={() => toggleCoupon(c.id)} className="text-xs px-3 py-1.5 border border-gray-200 rounded-lg hover:bg-gray-50 transition">{c.active ? "Disable" : "Enable"}</button><button onClick={() => setCoupons(prev => prev.filter(x => x.id !== c.id))} className="text-xs px-3 py-1.5 border border-red-100 text-red-400 rounded-lg hover:bg-red-50 transition"><Trash2 size={12} /></button></div></div></div>)}</div>
          </div>
        </div>
      )}
    </div>
  );

  // ─── Login Page ────────────────────────────────────────────────────────────

  const LoginPage = () => (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md">
        <div className="text-center mb-8"><p className="font-serif font-bold text-3xl text-[#1B2B4B] mb-2">Maison</p><p className="text-[#6B6560] text-sm">Welcome to considered living</p></div>
        <div className="bg-white rounded-3xl p-8 shadow-lg">
          <div className="flex rounded-xl overflow-hidden border border-gray-200 mb-6">{(["login", "register"] as const).map(t => <button key={t} onClick={() => setLoginTab(t)} className={`flex-1 py-2.5 text-sm font-medium transition ${loginTab === t ? "bg-[#1B2B4B] text-white" : "text-[#6B6560] hover:bg-gray-50"}`}>{t === "login" ? "Sign In" : "Create Account"}</button>)}</div>
          <div className="space-y-4">{loginTab === "register" && <input placeholder="Full Name" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm bg-white outline-none focus:border-[#1B2B4B]" />}<input type="email" placeholder="Email address" defaultValue="alex@example.com" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm bg-white outline-none focus:border-[#1B2B4B]" /><input type="password" placeholder="Password" defaultValue="••••••••" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm bg-white outline-none focus:border-[#1B2B4B]" />{loginTab === "register" && <input type="password" placeholder="Confirm Password" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm bg-white outline-none focus:border-[#1B2B4B]" />}</div>
          <button onClick={signIn} className="w-full mt-6 bg-[#1B2B4B] text-white py-3 rounded-xl font-medium hover:bg-[#C8965A] transition">{loginTab === "login" ? "Sign In" : "Create Account"}</button>
          <p className="text-center text-xs text-[#6B6560] mt-4">{loginTab === "login" ? "Don't have an account?" : "Already have an account?"}<button onClick={() => setLoginTab(loginTab === "login" ? "register" : "login")} className="text-[#C8965A] hover:underline ml-1">{loginTab === "login" ? "Sign up" : "Sign in"}</button></p>
        </div>
      </div>
    </div>
  );

  // ─── Payment Page ──────────────────────────────────────────────────────────

  const PaymentPage = () => (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8">
      <button onClick={() => goPage("shop")} className="flex items-center gap-2 text-[#6B6560] hover:text-[#1B2B4B] mb-6 text-sm transition"><ArrowLeft size={16} /> Continue Shopping</button>
      <h1 className="font-serif font-bold text-2xl sm:text-3xl text-[#1B2B4B] mb-8">Checkout</h1>
      <div className="grid lg:grid-cols-[1fr,380px] gap-8">
        <div className="space-y-6">
          <div className="bg-white rounded-2xl p-6 shadow-sm">
            <h2 className="font-serif font-bold text-lg text-[#1B2B4B] mb-5 flex items-center gap-2"><MapPin size={18} className="text-[#C8965A]" /> Delivery Address</h2>
            <div className="grid sm:grid-cols-2 gap-4">
              {([{ label: "Full Name", key: "name" as const }, { label: "Phone", key: "phone" as const }, { label: "Street Address", key: "street" as const, full: true }, { label: "City", key: "city" as const }, { label: "State", key: "state" as const }, { label: "PIN Code", key: "pincode" as const }] as { label: string; key: keyof typeof deliveryAddress; full?: boolean }[]).map(f => <div key={f.key} className={f.full ? "sm:col-span-2" : ""}><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-1.5">{f.label}</label><input value={deliveryAddress[f.key]} onChange={e => setDeliveryAddress(prev => ({ ...prev, [f.key]: e.target.value }))} className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm bg-white outline-none focus:border-[#1B2B4B]" /></div>)}
            </div>
          </div>
          <div className="bg-white rounded-2xl p-6 shadow-sm">
            <h2 className="font-serif font-bold text-lg text-[#1B2B4B] mb-5 flex items-center gap-2"><CreditCard size={18} className="text-[#C8965A]" /> Payment Method</h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              {([{ key: "upi" as PaymentMethod, label: "UPI", icon: <Smartphone size={20} /> }, { key: "card" as PaymentMethod, label: "Card", icon: <CreditCard size={20} /> }, { key: "netbanking" as PaymentMethod, label: "Net Banking", icon: <Building2 size={20} /> }, { key: "cod" as PaymentMethod, label: "Cash on Delivery", icon: <Banknote size={20} /> }]).map(m => <button key={m.key} onClick={() => setPaymentMethod(m.key)} className={`flex flex-col items-center gap-2 p-4 rounded-2xl border-2 transition ${paymentMethod === m.key ? "border-[#1B2B4B] bg-[#1B2B4B]/5" : "border-gray-200 hover:border-gray-300"}`}><div className={paymentMethod === m.key ? "text-[#1B2B4B]" : "text-[#6B6560]"}>{m.icon}</div><span className={`text-xs font-medium text-center leading-tight ${paymentMethod === m.key ? "text-[#1B2B4B]" : "text-[#6B6560]"}`}>{m.label}</span></button>)}
            </div>
            {paymentMethod === "upi" && <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">UPI ID</label><input value={upiId} onChange={e => setUpiId(e.target.value)} placeholder="yourname@paytm" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm outline-none focus:border-[#1B2B4B]" /><div className="flex gap-2 mt-3 flex-wrap">{["@paytm", "@gpay", "@phonepe", "@ybl"].map(a => <button key={a} onClick={() => setUpiId("user" + a)} className="text-xs px-3 py-1.5 bg-gray-100 rounded-full hover:bg-[#EDE8E0] transition">{a}</button>)}</div></div>}
            {paymentMethod === "card" && <div className="space-y-4"><div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Card Number</label><input value={cardNum} onChange={e => setCardNum(e.target.value)} placeholder="1234 5678 9012 3456" maxLength={19} className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm font-mono outline-none focus:border-[#1B2B4B]" /></div><div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Name on Card</label><input value={cardName} onChange={e => setCardName(e.target.value)} placeholder="Alex Johnson" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm outline-none focus:border-[#1B2B4B]" /></div><div className="grid grid-cols-2 gap-4"><div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Expiry</label><input value={cardExpiry} onChange={e => setCardExpiry(e.target.value)} placeholder="MM / YY" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm outline-none focus:border-[#1B2B4B]" /></div><div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">CVV</label><input value={cardCvv} onChange={e => setCardCvv(e.target.value)} placeholder="•••" maxLength={4} type="password" className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm outline-none focus:border-[#1B2B4B]" /></div></div></div>}
            {paymentMethod === "netbanking" && <div><label className="text-xs text-[#6B6560] uppercase tracking-wider block mb-2">Select Bank</label><select value={selectedBank} onChange={e => setSelectedBank(e.target.value)} className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm bg-white outline-none focus:border-[#1B2B4B]">{["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "Yes Bank", "PNB", "Bank of Baroda"].map(b => <option key={b}>{b}</option>)}</select></div>}
            {paymentMethod === "cod" && <div className="bg-amber-50 rounded-xl p-4 flex items-start gap-3"><Banknote size={20} className="text-amber-600 flex-shrink-0 mt-0.5" /><div><p className="text-amber-800 font-medium text-sm">Cash on Delivery</p><p className="text-amber-700 text-xs mt-1">Pay when your order arrives. Please keep exact change ready.</p></div></div>}
          </div>
        </div>
        <div>
          <div className="bg-white rounded-2xl p-6 shadow-sm sticky top-20">
            <h2 className="font-serif font-bold text-lg text-[#1B2B4B] mb-4">Order Summary</h2>
            <div className="space-y-3 mb-5 max-h-64 overflow-y-auto">{paymentItems.map((item, i) => <div key={i} className="flex items-center gap-3"><div className="relative flex-shrink-0"><img src={item.product.image} alt={item.product.name} className="w-14 h-14 rounded-xl object-cover" /><span className="absolute -top-1.5 -right-1.5 bg-[#1B2B4B] text-white text-xs rounded-full w-5 h-5 flex items-center justify-center font-bold">{item.qty}</span></div><div className="flex-1 min-w-0"><p className="font-medium text-sm truncate">{item.product.name}</p><p className="text-xs text-[#6B6560]">{item.product.category}</p></div><p className="font-bold text-sm text-[#1B2B4B] flex-shrink-0">${(item.product.price * item.qty).toFixed(2)}</p></div>)}</div>
            {currentUser.points >= 100 && <div className={`border rounded-xl p-3 mb-4 cursor-pointer transition ${redeemPoints ? "border-[#1B2B4B] bg-[#1B2B4B]/5" : "border-gray-200 hover:border-gray-300"}`} onClick={() => setRedeemPoints(v => !v)}><div className="flex items-center justify-between"><div className="flex items-center gap-2"><Zap size={16} className="text-[#C8965A]" /><span className="text-sm font-medium">{currentUser.points.toLocaleString()} pts available</span></div><div className={`w-4 h-4 rounded border-2 flex items-center justify-center ${redeemPoints ? "bg-[#1B2B4B] border-[#1B2B4B]" : "border-gray-300"}`}>{redeemPoints && <Check size={10} className="text-white" />}</div></div>{redeemPoints && <p className="text-xs text-emerald-600 mt-1 font-medium">-${pointsDiscount} discount applied</p>}</div>}
            <div className="border-t border-gray-100 pt-4 space-y-2">
              <div className="flex justify-between text-sm"><span className="text-[#6B6560]">Subtotal</span><span>${payTotal.toFixed(2)}</span></div>
              <div className="flex justify-between text-sm"><span className="text-[#6B6560]">Shipping</span><span className={payShipping === 0 ? "text-emerald-600" : ""}>{payShipping === 0 ? "Free" : `$${payShipping}`}</span></div>
              <div className="flex justify-between text-sm"><span className="text-[#6B6560]">Tax (8%)</span><span>${payTax}</span></div>
              {redeemPoints && <div className="flex justify-between text-sm text-emerald-600"><span>Points Redemption</span><span>-${pointsDiscount}</span></div>}
              <div className="flex justify-between font-bold text-[#1B2B4B] text-lg border-t border-gray-100 pt-3"><span>Total</span><span>${payGrand.toFixed(2)}</span></div>
              <p className="text-xs text-[#6B6560] text-center">{formatINR(payGrand)}</p>
            </div>
            <button onClick={placeOrder} className="w-full mt-4 bg-[#C8965A] text-white py-4 rounded-xl font-bold text-base hover:bg-[#b07c45] transition shadow-md">Place Order · ${payGrand.toFixed(2)}</button>
            <div className="flex items-center justify-center gap-2 mt-3 text-xs text-[#6B6560]"><Check size={12} className="text-emerald-500" /> Secure &amp; Encrypted Payment</div>
          </div>
        </div>
      </div>
    </div>
  );

  // ─── Confirmed Page ────────────────────────────────────────────────────────

  const ConfirmedPage = () => {
    const co = orders.find(o => o.id === confirmedOrderId) ?? orders[0];
    if (!co) return null;
    const tax = Math.round(co.total * 0.08); const shipping = co.total > 150 ? 0 : 12; const grand = co.total + shipping + tax;
    const estDate = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
    return (
      <div className="max-w-2xl mx-auto px-4 sm:px-6 py-12">
        <div className="text-center mb-10"><div className="w-20 h-20 rounded-full bg-emerald-100 flex items-center justify-center mx-auto mb-5"><CheckCircle size={40} className="text-emerald-600" /></div><h1 className="font-serif font-bold text-3xl text-[#1B2B4B] mb-2">Order Placed!</h1><p className="text-[#6B6560]">Thank you! We&apos;ll get it to you by <strong>{estDate}</strong>.</p></div>
        <div className="bg-white rounded-3xl shadow-lg overflow-hidden mb-6">
          <div className="bg-[#1B2B4B] px-8 py-6 flex items-center justify-between"><div><p className="text-white font-serif font-bold text-2xl">Maison</p><p className="text-white/50 text-xs mt-0.5">hello@maison.shop</p></div><div className="text-right"><p className="text-[#C8965A] text-xs font-medium uppercase">Invoice</p><p className="text-white font-mono text-sm">{co.id}</p><p className="text-white/50 text-xs">{co.date}</p></div></div>
          <div className="px-8 py-6">
            <div className="bg-blue-50 rounded-2xl p-4 mb-5 flex items-center gap-3"><Truck size={20} className="text-blue-600 flex-shrink-0" /><div><p className="text-sm font-medium text-blue-800">Estimated Delivery: {estDate}</p><p className="text-xs font-mono text-blue-700 mt-0.5">Tracking: {co.tracking}</p></div></div>
            <div className="space-y-3 mb-5">{co.items.map((item, i) => <div key={i} className="flex items-center gap-3 p-3 bg-gray-50 rounded-xl"><img src={item.image} alt={item.name} className="w-12 h-12 rounded-xl object-cover" /><div className="flex-1 min-w-0"><p className="font-medium text-sm truncate">{item.name}</p><p className="text-xs text-[#6B6560]">Qty: {item.qty} × ${item.price}</p></div><p className="font-bold text-sm text-[#1B2B4B]">${(item.price * item.qty).toFixed(2)}</p></div>)}</div>
            <div className="border-t border-gray-100 pt-4 space-y-2"><div className="flex justify-between text-sm"><span className="text-[#6B6560]">Subtotal</span><span>${co.total.toFixed(2)}</span></div><div className="flex justify-between text-sm"><span className="text-[#6B6560]">Shipping</span><span className={shipping === 0 ? "text-emerald-600" : ""}>{shipping === 0 ? "Free" : `$${shipping}`}</span></div><div className="flex justify-between text-sm"><span className="text-[#6B6560]">Tax</span><span>${tax}</span></div><div className="flex justify-between font-bold text-[#1B2B4B] text-lg border-t border-gray-100 pt-3"><span>Total Paid</span><div className="text-right"><p>${grand.toFixed(2)}</p><p className="text-xs text-[#6B6560] font-normal">{formatINR(grand)}</p></div></div></div>
          </div>
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <button onClick={() => { setAccTab("orders"); goPage("account"); }} className="flex-1 flex items-center justify-center gap-2 border-2 border-[#1B2B4B] text-[#1B2B4B] py-3 rounded-xl font-medium hover:bg-[#1B2B4B] hover:text-white transition"><Package size={16} /> Track Order</button>
          <button className="flex-1 flex items-center justify-center gap-2 border border-gray-200 py-3 rounded-xl font-medium hover:bg-gray-50 text-[#6B6560] transition"><Printer size={16} /> Invoice</button>
          <button onClick={() => goPage("shop")} className="flex-1 bg-[#C8965A] text-white py-3 rounded-xl font-medium hover:bg-[#b07c45] transition">Continue Shopping</button>
        </div>
      </div>
    );
  };

  // ─── Footer ────────────────────────────────────────────────────────────────

  const Footer = () => (
    <footer className="bg-[#1B2B4B] text-white/70 mt-16">
      <div className="max-w-7xl mx-auto px-6 py-12 grid sm:grid-cols-2 md:grid-cols-4 gap-8">
        <div><p className="font-serif font-bold text-white text-xl mb-3">Maison</p><p className="text-sm leading-relaxed mb-4">Curated objects for considered living. Made by hand, built to last.</p><div className="flex gap-2">{["Artisan", "Sustainable", "Timeless"].map(t => <span key={t} className="text-xs bg-white/10 px-2 py-1 rounded-full">{t}</span>)}</div></div>
        {[{ title: "Shop", links: ["All Products", "New Arrivals", "Sale", "Bestsellers"] }, { title: "Company", links: ["Our Story", "Makers", "Sustainability", "Press"] }, { title: "Support", links: ["FAQ", "Shipping", "Returns", "Contact"] }].map(col => <div key={col.title}><p className="text-white font-medium mb-3 text-sm">{col.title}</p><ul className="space-y-2">{col.links.map(l => <li key={l}><button className="text-sm hover:text-white transition">{l}</button></li>)}</ul></div>)}
      </div>
      <div className="border-t border-white/10 px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs">
        <span>© 2025 Maison. All rights reserved.</span>
        <div className="flex items-center gap-1"><Shield size={12} className="text-[#C8965A]" /><span>Secure payments · Free returns · Authenticity guaranteed</span></div>
      </div>
    </footer>
  );

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-background" style={{ fontFamily: "'DM Sans', sans-serif" }}>
      {cancelOrderOpen && <CancelModal />}
      {searchOpen && <SearchOverlay />}
      {filterOpen && <FilterPanel />}
      {manageOrderOpen && <ManageOrderModal />}
      {addProductOpen && <AddProductModal />}
      {csvUploadOpen && <CSVModal />}
      <Navbar />
      <CartDrawer />
      <main className={page === "our-story" ? "relative" : ""}>
        {page === "shop" && <ShopPage />}
        {page === "product" && <ProductPage />}
        {page === "our-story" && <OurStoryPage />}
        {page === "hub" && <HubPage />}
        {page === "account" && <AccountPage />}
        {page === "vendor" && <VendorPage />}
        {page === "admin" && <AdminPage />}
        {page === "login" && <LoginPage />}
        {page === "payment" && <PaymentPage />}
        {page === "confirmed" && <ConfirmedPage />}
      </main>
      {page !== "payment" && page !== "confirmed" && <Footer />}
    </div>
  );
}

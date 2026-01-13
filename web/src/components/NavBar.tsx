interface NavBarProps {
  onThemeToggle: () => void;
  isDark: boolean;
}

export default function NavBar({ onThemeToggle, isDark }: NavBarProps) {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-white dark:bg-navy border-b border-gray-200 dark:border-gray-700">
      <div className="px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/app/logo.png"
            alt="FaraMesh"
            className="h-8 w-8"
            onError={(e) => {
              // Fallback if logo doesn't exist
              (e.target as HTMLImageElement).style.display = 'none';
            }}
          />
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-gray-900 dark:text-white">FaraCore</h1>
          </div>
        </div>
        <button
          onClick={onThemeToggle}
          className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-charcoal text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-graphite transition-colors text-sm font-medium"
        >
          {isDark ? '☀️ Light' : '🌙 Dark'}
        </button>
      </div>
    </nav>
  );
}

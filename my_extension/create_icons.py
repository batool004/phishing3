from PIL import Image, ImageDraw
import os

# Create icons folder inside my_extension
if not os.path.exists('my_extension/icons'):
    os.makedirs('my_extension/icons')

def create_icon(size, filename):
    """Create an icon with a specific size"""
    
    # Create image with purple background
    img = Image.new('RGB', (size, size), color='#667eea')
    draw = ImageDraw.Draw(img)
    
    # Draw white circle in the center
    draw.ellipse(
        (size * 0.2, size * 0.2, size * 0.8, size * 0.8),
        fill='white'
    )
    
    # Draw shield shape (simple design)
    # Top part of shield (triangle)
    draw.polygon([
        (size * 0.35, size * 0.5),   # Left
        (size * 0.5, size * 0.3),    # Top
        (size * 0.65, size * 0.5)    # Right
    ], fill='#667eea')
    
    # Bottom part of shield (rectangle)
    draw.rectangle(
        (size * 0.35, size * 0.5, size * 0.65, size * 0.75),
        fill='#667eea'
    )
    
    # Draw security checkmark (✓) for larger sizes
    if size >= 48:
        draw.line(
            [(size * 0.4, size * 0.6), (size * 0.5, size * 0.7)],
            fill='white',
            width=max(2, size // 20)
        )
        draw.line(
            [(size * 0.5, size * 0.7), (size * 0.7, size * 0.45)],
            fill='white',
            width=max(2, size // 20)
        )
    
    # Save image
    img.save(f'my_extension/icons/{filename}')
    print(f"✅ Created {filename} ({size}x{size})")


# Generate required icon sizes
print("🖼️ Generating icons...")
print("-" * 40)

create_icon(16, 'icon16.png')
create_icon(48, 'icon48.png')
create_icon(128, 'icon.png')

print("-" * 40)
print("\n🎉 All icons generated successfully!")
print("📁 Location: my_extension/icons/")